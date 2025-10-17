//logged by iyad

const express = require('express');
const path = require('path');
const session = require('express-session');
const { createClient } = require('@libsql/client');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');


const app = express();

// Middleware to parse JSON bodies
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
console.log('TURSO_DATABASE_URL:', process.env.TURSO_DATABASE_URL);
console.log('TURSO_AUTH_TOKEN:', !!process.env.TURSO_AUTH_TOKEN);
console.log('TURSO_AUTH_TOKEN length:', process.env.TURSO_AUTH_TOKEN.length);

console.log('Raw token:', JSON.stringify(process.env.TURSO_AUTH_TOKEN));
console.log('Token length:', process.env.TURSO_AUTH_TOKEN.length);
// Initialize Turso client
let db;
try {
  db = createClient({
    url: process.env.TURSO_DATABASE_URL,
    authToken: process.env.TURSO_AUTH_TOKEN?.trim()
  });
  console.log('Turso client initialized');
} catch (err) {
  console.error('Failed to initialize Turso client:', err);
  process.exit(1);
}



// Add session middleware with better configuration for Vercel
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax'
  }
}));



app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/home', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

app.get('/map', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'map.html'));
});

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.cookies?.token; // now req.cookies exists
  if (!token) {
    return res.redirect('/login');
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.redirect('/login');
  }
}


// API endpoint to get all parking spaces
// API endpoint to get all locations
app.get('/api/locations', async (req, res) => {
  try {
    const result = await db.execute('SELECT * FROM locations');

    const locations = result.rows.map(row => ({
      id: row.id,
      imageIndex: row.image_index,
      currentAvailable: row.current_available,
      addressLocation: row.adress_location,
      averagePrice: row.avarage_price,
      redirect: '/map'
    }));

    res.json(locations);
  } catch (err) {
    console.error('Error fetching locations:', err);
    res.status(500).json({ error: 'Failed to fetch locations', details: err.message });
  }
});

// API endpoint to get parking spaces for a specific location



// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  // Check that Turso client is initialized correctly
  if (!db || !process.env.TURSO_DATABASE_URL || !process.env.TURSO_AUTH_TOKEN) {
    console.error('Turso client not initialized or missing env vars');
    return res.status(500).json({
      error: 'Server misconfiguration',
      details: 'Check TURSO_DATABASE_URL and TURSO_AUTH_TOKEN environment variables'
    });
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

const token = jwt.sign(
  { username: user.username, email: user.email, role: user.role },
  process.env.JWT_SECRET,
  { expiresIn: '24h' }
);

res.cookie('token', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  maxAge: 24 * 60 * 60 * 1000
});

res.json({ success: true });



  } catch (err) {
    console.error('Login error:', err);

    // Extra check for auth token/header errors
    if (err.message.includes('Bearer') || err.message.includes('HTTP header')) {
      return res.status(500).json({
        error: 'Database authentication error',
        details: 'Check TURSO_AUTH_TOKEN value in environment variables'
      });
    }

    res.status(500).json({ error: 'Database error', details: err.message });
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
    res.status(500).json({ error: 'Failed to register user', details: err.message });
  }
});

// Session check endpoint
app.get('/api/auth/check', (req, res) => {
  res.json({ isLoggedIn: !!req.session.user });
});


// Root route
app.get('/', (req, res) => {

  if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable not set');
}

  if (!req.session.user) {
    return res.redirect('/home');
  }
  return res.redirect('/home');
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
    res.status(500).json({ error: 'Failed to fetch user data', details: err.message });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    env: {
      hasTursoUrl: !!process.env.TURSO_DATABASE_URL,
      hasTursoToken: !!process.env.TURSO_AUTH_TOKEN,
      hasSessionSecret: !!process.env.SESSION_SECRET
    }
  });
});


// API endpoint to get maps for a specific location
app.get('/api/maps/:location_id', async (req, res) => {
  try {
    const locationId = req.params.location_id;
    const result = await db.execute({
      sql: 'SELECT * FROM maps WHERE location_index = ? ORDER BY floor ASC',
      args: [locationId]
    });

    const maps = result.rows.map(row => ({
      id: row.id,
      locationIndex: row.location_index,
      floor: row.floor,
      floorsImageIndex: row.floors_image_index
    }));

    res.json(maps);
  } catch (err) {
    console.error('Error fetching maps:', err);
    res.status(500).json({ error: 'Failed to fetch maps', details: err.message });
  }
});

// API endpoint to get parking spaces for a specific location
app.get('/api/parking/:location_id', async (req, res) => {
  try {
    const locationId = req.params.location_id;
    const result = await db.execute({
      sql: 'SELECT * FROM parking_spaces WHERE location_index = ? ORDER BY index ASC',
      args: [locationId]
    });

    const spaces = result.rows.map(row => ({
      id: row.id,
      state: row.state,
      feature: row.exclusive,
      price: row.price,
      index: row.index,
      floor: row.floor,
      locationIndex: row.location_index,
      locationX: row.location_x,
      locationY: row.location_y,
      sizeX: row.width,
      sizeY: row.height,
      plate: row.plate,
      daysToOccupy: row.days_to_occupy,
      lastUpdate: row.last_update,
      restrictionStart: row.restriction_start,
      restrictionEnd: row.restriction_end,
      restrictionFrequency: row.restriction_frequency
    }));

    res.json(spaces);
  } catch (err) {
    console.error('Error fetching parking spaces:', err);
    res.status(500).json({ error: 'Failed to fetch parking spaces', details: err.message });
  }
});

// API endpoint to reserve a parking space (updated to use 'index' column)
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
      sql: 'SELECT * FROM parking_spaces WHERE index = ?',
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
            WHERE index = ?`,
      args: ['taken', plate, days, currentTime, index]
    });

    // Fetch the updated row
    const updatedResult = await db.execute({
      sql: 'SELECT * FROM parking_spaces WHERE index = ?',
      args: [index]
    });

    const updatedRow = updatedResult.rows[0];
    const updatedSpace = {
      id: updatedRow.id,
      state: updatedRow.state,
      feature: updatedRow.exclusive,
      price: updatedRow.price,
      index: updatedRow.index,
      floor: updatedRow.floor,
      locationIndex: updatedRow.location_index,
      locationX: updatedRow.location_x,
      locationY: updatedRow.location_y,
      sizeX: updatedRow.width,
      sizeY: updatedRow.height,
      plate: updatedRow.plate,
      daysToOccupy: updatedRow.days_to_occupy,
      lastUpdate: updatedRow.last_update,
      restrictionStart: updatedRow.restriction_start,
      restrictionEnd: updatedRow.restriction_end,
      restrictionFrequency: updatedRow.restriction_frequency
    };

    console.log('Reservation successful:', updatedSpace);
    res.json(updatedSpace);
  } catch (err) {
    console.error('Error during reservation:', err);
    res.status(500).json({ error: 'Failed to reserve parking space', details: err.message });
  }
});
// Export for Vercel
module.exports = app;

//antivercel
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});