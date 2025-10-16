//logged by iyad

const express = require('express'); // Import Express framework
const path = require('path'); // Import path module for handling file paths
const session = require('express-session');
const app = express(); // Create an Express application
let publicPath = path.join(__dirname, 'frontend'); // Define the path to the frontend directory

// Middleware to parse JSON bodies
app.use(express.json());

const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('parking_system.db');

// Create accounts table if not exists
db.run(`CREATE TABLE IF NOT EXISTS accounts (
  username TEXT PRIMARY KEY,
  email TEXT UNIQUE,
  password TEXT,
  role TEXT DEFAULT 'user',
  slotIndexTaken TEXT,
  locationTaken TEXT
)`, (err) => {
  if (err) {
    console.error('Error creating accounts table:', err);
  } else {
    console.log('Accounts table ready');
  }
});



console.log('Public path:', publicPath); // Log the public path for debugging

app.use(express.static(path.join(__dirname, "frontend"))); // Serve static files from the frontend directory

// Add session middleware
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false, // set to true if using https
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.user) {
    if (req.xhr) { // AJAX request
      return res.status(401).json({ error: 'Authentication required' });
    }
    return res.redirect('/login');
  }
  next();
}

// API endpoint to get all parking spaces
app.get('/api/parking', (req, res) => {
  db.all('SELECT * FROM parking_spaces ORDER BY index_number', (err, rows) => {
    if (err) {
      console.error('Error fetching parking spaces:', err);
      res.status(500).json({ error: 'Failed to fetch parking spaces' });
    } else {
      // Map database columns to frontend expected format
      const spaces = rows.map(row => ({
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
    }
  });
});

// API endpoint to reserve a parking space
app.post('/api/parking/reserve', (req, res) => {
  const { index, plate, days } = req.body;

  console.log('Reservation request:', { index, plate, days });

  if (!index || !plate || !days || days <= 0) {
    return res.status(400).json({ error: 'Invalid reservation data' });
  }

  const currentTime = new Date().toISOString();

  // First check if the space is available
  db.get('SELECT * FROM parking_spaces WHERE index_number = ?', [index], (err, row) => {
    if (err) {
      console.error('Error checking space:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (!row) {
      return res.status(404).json({ error: 'Parking space not found' });
    }

    console.log('Found space:', row);

    if (row.state !== 'available' && row.exclusive !== 'available') {
      return res.status(400).json({ error: 'Parking space is not available' });
    }

    // Update the parking space
    db.run(
      `UPDATE parking_spaces 
       SET state = ?, plate = ?, days_to_occupy = ?, last_update = ? 
       WHERE index_number = ?`,
      ['taken', plate, days, currentTime, index],
      function(err) {
        if (err) {
          console.error('Error updating parking space:', err);
          return res.status(500).json({ error: 'Failed to reserve parking space' });
        }

        console.log(`Updated ${this.changes} row(s)`);

        // Return the updated row
        db.get('SELECT * FROM parking_spaces WHERE index_number = ?', [index], (err, updatedRow) => {
          if (err) {
            console.error('Error fetching updated row:', err);
            return res.status(500).json({ error: 'Reservation successful but failed to fetch updated data' });
          }

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
        });
      }
    );
  });
});

// Update login endpoint to set session
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  db.get('SELECT * FROM accounts WHERE email = ? AND password = ?', 
    [email, password],
    (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
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
    });
});

// Add logout endpoint
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ success: true });
  });
});

// Add register endpoint
app.post('/api/auth/register', (req, res) => {
  const { username, email, password } = req.body;
  
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }

  // Check if email or username already exists
  db.get('SELECT * FROM accounts WHERE email = ? OR username = ?', [email, username], (err, existing) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (existing) {
      return res.status(409).json({ error: 'Email or username already exists' });
    }

    // Insert new user
    db.run('INSERT INTO accounts (username, email, password, role) VALUES (?, ?, ?, ?)',
      [username, email, password, 'user'],
      function(err) {
        if (err) {
          console.error('Registration error:', err);
          return res.status(500).json({ error: 'Failed to register user' });
        }
        res.json({ success: true, username, email });
      });
  });
});

// Add session check endpoint
app.get('/api/auth/check', (req, res) => {
  res.json({ isLoggedIn: !!req.session.user });
});

// Update login route to handle auto-login
app.get('/login', (req, res) => {
  if (req.session.user) {
    if (req.query.email && req.query.pass) {
      // If credentials provided, show login page with auto-fill
      res.sendFile(path.join(publicPath, 'login.html'));
    }
  } else {
    res.sendFile(path.join(publicPath, 'login.html'));
  }
});

// Root route - redirect to appropriate page based on auth status
app.get('/', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  return res.redirect('/home');
});

// Protected routes - require authentication
app.get('/home', requireAuth, (req, res) => {
  res.sendFile(path.join(publicPath, 'home.html')); 
});

app.get('/map', requireAuth, (req, res) => {
  res.sendFile(path.join(publicPath, 'map.html'));
});

// Add endpoint to get user data
app.get('/api/auth/user', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not logged in' });
  }
  
  db.get('SELECT email, password FROM accounts WHERE email = ?', 
    [req.session.user.email],
    (err, user) => {
      if (err || !user) {
        return res.status(500).json({ error: 'Failed to fetch user data' });
      }
      res.json(user);
    });
});

app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
  console.log('Database reset with unique parking space indexes');
});