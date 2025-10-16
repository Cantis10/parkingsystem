//logged by iyad

const express = require('express');
const path = require('path');
const session = require('express-session');
const { createClient } = require('@libsql/client');

const app = express();
let publicPath = path.join(__dirname, 'frontend');

// Middleware to parse JSON bodies
app.use(express.json());

// Initialize Turso client with error handling
let db;
try {
  if (!process.env.TURSO_DATABASE_URL || !process.env.TURSO_AUTH_TOKEN) {
    throw new Error('Missing Turso environment variables');
  }
  
  db = createClient({
    url: process.env.TURSO_DATABASE_URL,
    authToken: process.env.TURSO_AUTH_TOKEN
  });
  
  console.log('Turso client initialized successfully');
} catch (err) {
  console.error('Failed to initialize Turso client:', err);
  process.exit(1);
}

// Create tables if not exists
async function initializeDatabase() {
  try {
    // Create accounts table
    await db.execute(`CREATE TABLE IF NOT EXISTS accounts (
      username TEXT PRIMARY KEY,
      email TEXT UNIQUE,
      password TEXT,
      role TEXT DEFAULT 'user',
      slotIndexTaken TEXT,
      locationTaken TEXT
    )`);

    // Create parking_spaces table if you have one
    await db.execute(`CREATE TABLE IF NOT EXISTS parking_spaces (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      state TEXT DEFAULT 'available',
      exclusive TEXT,
      price REAL,
      index_number INTEGER UNIQUE,
      floor INTEGER,
      location_x REAL,
      location_y REAL,
      width REAL,
      height REAL,
      plate TEXT,
      days_to_occupy INTEGER,
      last_update TEXT
    )`);

    console.log('Database tables ready');
  } catch (err) {
    console.error('Error creating tables:', err);
  }
}

// Initialize database tables
initializeDatabase().catch(err => {
  console.error('Database initialization failed:', err);
});

console.log('Public path:', publicPath);

app.use(express.static(path.join(__dirname, "frontend")));

// Add session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.user) {
    if (req.xhr) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    return res.redirect('/login');
  }
  next();
}

// API endpoint to get all parking spaces
app.get('/api/parking', async (req, res) => {
  try {
    const result = await db.execute('SELECT * FROM parking_spaces ORDER BY index_number');
    
    const spaces = result.rows.map(row => ({
      id: row.id,
      state: row.state,
      feature: row.exclusive,
      price: row.price,
      index: row.index_number,
      floor: row.floor,
      locationX: row.location_x,
      locationY: row.location_y,
      sizeX: row.width,
      sizeY: row.height,
      plate: row.plate,
      daysToOccupy: row.days_to_occupy,
      lastUpdate: row.last_update
    }));
    
    res.json(spaces);
  } catch (err) {
    console.error('Error fetching parking spaces:', err);
    res.status(500).json({ error: 'Failed to fetch parking spaces' });
  }
});

// API endpoint to reserve a parking space
app.post('/api/parking/reserve', async (req, res) => {
  const { index, plate, days } = req.body;

  console.log('Reservation request:', { index, plate, days });

  if (!index || !plate || !days || days <= 0) {
    return res.status(400).json({ error: 'Invalid reservation data' });
  }

  const currentTime = new Date().toISOString();

  try {
    // First check if the space is available
    const checkResult = await db.execute({
      sql: 'SELECT * FROM parking_spaces WHERE index_number = ?',
      args: [index]
    });

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Parking space not found' });
    }

    const row = checkResult.rows[0];
    console.log('Found space:', row);

    if (row.state !== 'available' && row.exclusive !== 'available') {
      return res.status(400).json({ error: 'Parking space is not available' });
    }

    // Update the parking space
    await db.execute({
      sql: `UPDATE parking_spaces 
            SET state = ?, plate = ?, days_to_occupy = ?, last_update = ? 
            WHERE index_number = ?`,
      args: ['taken', plate, days, currentTime, index]
    });

    // Fetch the updated row
    const updatedResult = await db.execute({
      sql: 'SELECT * FROM parking_spaces WHERE index_number = ?',
      args: [index]
    });

    const updatedRow = updatedResult.rows[0];
    const updatedSpace = {
      id: updatedRow.id,
      state: updatedRow.state,
      feature: updatedRow.exclusive,
      price: updatedRow.price,
      index: updatedRow.index_number,
      floor: updatedRow.floor,
      locationX: updatedRow.location_x,
      locationY: updatedRow.location_y,
      sizeX: updatedRow.width,
      sizeY: updatedRow.height,
      plate: updatedRow.plate,
      daysToOccupy: updatedRow.days_to_occupy,
      lastUpdate: updatedRow.last_update
    };

    console.log('Reservation successful:', updatedSpace);
    res.json(updatedSpace);
  } catch (err) {
    console.error('Error during reservation:', err);
    res.status(500).json({ error: 'Failed to reserve parking space' });
  }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  try {
    const result = await db.execute({
      sql: 'SELECT * FROM accounts WHERE email = ? AND password = ?',
      args: [email, password]
    });

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    
    // Set session
    req.session.user = {
      username: user.username,
      email: user.email,
      role: user.role
    };
    
    res.json({ 
      username: user.username,
      email: user.email,
      role: user.role
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Logout endpoint
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ success: true });
  });
});

// Register endpoint
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }

  try {
    // Check if email or username already exists
    const checkResult = await db.execute({
      sql: 'SELECT * FROM accounts WHERE email = ? OR username = ?',
      args: [email, username]
    });

    if (checkResult.rows.length > 0) {
      return res.status(409).json({ error: 'Email or username already exists' });
    }

    // Insert new user
    await db.execute({
      sql: 'INSERT INTO accounts (username, email, password, role) VALUES (?, ?, ?, ?)',
      args: [username, email, password, 'user']
    });

    res.json({ success: true, username, email });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// Session check endpoint
app.get('/api/auth/check', (req, res) => {
  res.json({ isLoggedIn: !!req.session.user });
});

// Login route
app.get('/login', (req, res) => {
  if (req.session.user) {
    if (req.query.email && req.query.pass) {
      res.sendFile(path.join(publicPath, 'login.html'));
    }
  } else {
    res.sendFile(path.join(publicPath, 'login.html'));
  }
});

// Root route
app.get('/', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  return res.redirect('/home');
});

// Protected routes
app.get('/home', requireAuth, (req, res) => {
  res.sendFile(path.join(publicPath, 'home.html')); 
});

app.get('/map', requireAuth, (req, res) => {
  res.sendFile(path.join(publicPath, 'map.html'));
});

// Get user data endpoint
app.get('/api/auth/user', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not logged in' });
  }
  
  try {
    const result = await db.execute({
      sql: 'SELECT email, password FROM accounts WHERE email = ?',
      args: [req.session.user.email]
    });

    if (result.rows.length === 0) {
      return res.status(500).json({ error: 'Failed to fetch user data' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
  console.log('Using Turso database');
});