//logged by iyad

const express = require('express');
const path = require('path');
const session = require('express-session');
const { createClient } = require('@libsql/client');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
require('dotenv').config();
const PORT = process.env.PORT || 3000;
const app = express();

const BASE_URL =
  process.env.BASE_URL ||
  (process.env.CODESPACE_NAME
    ? `https://${process.env.CODESPACE_NAME}-3000.app.github.dev`
    : `http://localhost:${process.env.PORT || 3000}`);

console.log('✅ BASE_URL set to:', BASE_URL);

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

app.get('/api/auth/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userEmail = decoded.email;

    await db.execute(`
      CREATE TABLE IF NOT EXISTS pending_verifications (
        email TEXT PRIMARY KEY,
        verified INTEGER DEFAULT 0
      );
    `);

    await db.execute({
      sql: `
        INSERT INTO pending_verifications (email, verified)
        VALUES (?, 1)
        ON CONFLICT(email) DO UPDATE SET verified = 1;
      `,
      args: [userEmail],
    });

    console.log(`✅ Email verified: ${userEmail}`);

    res.json({ success: true, email: userEmail, message: 'Email verified. You may now complete registration.' });

  } catch (err) {
    console.error('Verification error:', err);
    res.status(400).json({ success: false, error: 'Invalid or expired verification link.' });
  }
});








//add mail transporter
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587, // or 465 for SSL
  secure: false, // true for 465, false for 587
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false // May help with cert issues
  }
});


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

app.get('/settings', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'settings.html'));
});

app.get('/homepage', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'homepage.html'));
});

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.redirect('/login');

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // store user info
    next();
  } catch (err) {
    console.error('JWT verification failed:', err.message);
    return res.redirect('/login');
  }
}

function getUserFromToken(req) {
  const token = req.cookies?.token;
  if (!token) return null;
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

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
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password required' });

  try {
    const result = await db.execute({
      sql: 'SELECT * FROM accounts WHERE LOWER(email) = LOWER(?) AND password = ?',
      args: [email, password]
    });

    if (result.rows.length === 0)
      return res.status(401).json({ error: 'Invalid credentials' });


    const user = result.rows[0];
    if (!user.verified) {
      return res.status(403).json({ error: 'Please verify your email before logging in.' });
    }
    const token = jwt.sign(
      {
        username: user.username,
        email: user.email,
        role: user.role,
        liscense_plate: user.liscense_plate,
        slot_index_taken: user.slot_index_taken,
        location_taken: user.location_taken
      },
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
    res.status(500).json({ error: 'Login failed', details: err.message });
  }
});


// Logout endpoint
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});





// Updated Register endpoint with automatic verification email
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, liscense_plate } = req.body;
  if (!username || !email || !password || !liscense_plate)
    return res.status(400).json({ error: 'All fields required' });

  try {
    // Check if user already exists
    const existing = await db.execute({
      sql: 'SELECT * FROM accounts WHERE email = ? OR username = ?',
      args: [email, username]
    });

    if (existing.rows.length > 0)
      return res.status(409).json({ error: 'Email or username already exists' });

    // Check if email has been verified
    const verification = await db.execute({
      sql: 'SELECT verified FROM pending_verifications WHERE email = ?',
      args: [email]
    });

    // If not verified, send verification email
    if (verification.rows.length === 0 || !verification.rows[0].verified) {
      console.log(`📧 User ${email} not verified. Sending verification email...`);

      // Generate JWT token for verification
      const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '24h' });
      const verificationLink = `${BASE_URL}/api/auth/verify/${encodeURIComponent(token)}`;

      // Send verification email
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Verify your email address',
        html: `
          <h2>Verify your email address</h2>
          <p>Click below to verify this email before completing your registration:</p>
          <p><a href="${verificationLink}" target="_blank">${verificationLink}</a></p>
          <p>If you didn't request this, ignore it.</p>
        `
      };

      try {
        await transporter.sendMail(mailOptions);
        console.log('📧 Verification email sent to:', email);
      } catch (emailErr) {
        console.error('❌ Failed to send verification email:', emailErr);
        return res.status(500).json({
          error: 'Failed to send verification email. Please try again later.',
          details: emailErr.message
        });
      }

      return res.status(403).json({
        error: 'Please verify your email before registering. A verification link has been sent to your email.',
        verificationSent: true
      });
    }

    // ✅ Email is verified, proceed with registration
    console.log(`✅ User ${email} is verified. Creating account...`);

    await db.execute({
      sql: `INSERT INTO accounts 
            (username, email, password, role, liscense_plate, verified, slot_index_taken, location_taken) 
            VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)`,
      args: [username, email, password, 'user', liscense_plate, true]
    });

    // ✅ Remove from pending_verifications
    await db.execute({
      sql: 'DELETE FROM pending_verifications WHERE email = ?',
      args: [email]
    });

    // ✅ Auto-login token
    const token = jwt.sign(
      {
        username,
        email,
        role: 'user',
        liscense_plate,
        slot_index_taken: null,
        location_taken: null
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
    });

    console.log(`✅ Account created successfully for ${email}`);
    res.json({ success: true, message: 'Account created and logged in automatically!' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed', details: err.message });
  }
});






// Session check endpoint
app.get('/api/auth/check', (req, res) => {
  const user = getUserFromToken(req);
  res.json({ isLoggedIn: !!user });
});

// Root route
app.get('/', (req, res) => {
  const token = req.cookies?.token;
  if (!token) return res.redirect('/homepage');


  jwt.verify(token, process.env.JWT_SECRET);
  return res.redirect('/home');

});


app.get('/admin-map', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-map.html'));
});

app.post('/api/admin/parking/update', async (req, res) => {
  const user = getUserFromToken(req);
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  if (user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin privileges required' });
  }

  const {
    index,
    location_x,
    location_y,
    width,
    height,
    floor,
    price,
    state,
    exclusive,
    plate,
    days_to_occupy,
    restriction_start,
    restriction_end,
    restriction_frequency
  } = req.body;

  if (!index) {
    return res.status(400).json({ error: 'Parking space index required' });
  }

  try {
    // Verify the parking space exists and get its location_index
    const spaceResult = await db.execute({
      sql: 'SELECT location_index FROM parking_spaces WHERE "index" = ?',
      args: [index]
    });

    if (spaceResult.rows.length === 0) {
      return res.status(404).json({ error: 'Parking space not found' });
    }

    const locationIndex = spaceResult.rows[0].location_index;

    // Verify admin has access to this location
    if (user.location_index_admin && parseInt(user.location_index_admin) !== parseInt(locationIndex)) {
      return res.status(403).json({ error: 'You do not have admin access to this location' });
    }

    // Update the parking space
    const currentTime = new Date().toISOString();
    await db.execute({
      sql: `UPDATE parking_spaces 
            SET location_x = ?, location_y = ?, width = ?, height = ?, 
                floor = ?, price = ?, state = ?, exclusive = ?, 
                plate = ?, days_to_occupy = ?, last_update = ?,
                restriction_start = ?, restriction_end = ?, restriction_frequency = ?
            WHERE "index" = ?`,
      args: [
        location_x, location_y, width, height,
        floor, price, state, exclusive,
        plate, days_to_occupy, currentTime,
        restriction_start, restriction_end, restriction_frequency,
        index
      ]
    });

    // Update the location's available slots count
    await updateLocationAvailableSlots(locationIndex);

    res.json({ success: true, message: 'Parking space updated successfully' });
  } catch (err) {
    console.error('Error updating parking space:', err);
    res.status(500).json({ error: 'Failed to update parking space', details: err.message });
  }
});

// Update account settings endpoint
app.post('/api/account/update', async (req, res) => {
  const user = getUserFromToken(req);
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const { currentPassword, newUsername, newPassword, newLicensePlate } = req.body;

  if (!currentPassword) {
    return res.status(400).json({ error: 'Current password is required to make changes' });
  }

  // Validate that at least one field is being updated
  if (!newUsername && !newPassword && !newLicensePlate) {
    return res.status(400).json({ error: 'At least one field must be provided to update' });
  }

  try {
    // Verify current password
    const verifyResult = await db.execute({
      sql: 'SELECT * FROM accounts WHERE email = ? AND password = ?',
      args: [user.email, currentPassword]
    });

    if (verifyResult.rows.length === 0) {
      return res.status(403).json({ error: 'Current password is incorrect' });
    }

    // Check if new username already exists (if username is being changed)
    if (newUsername && newUsername !== user.username) {
      const usernameCheck = await db.execute({
        sql: 'SELECT * FROM accounts WHERE username = ? AND email != ?',
        args: [newUsername, user.email]
      });

      if (usernameCheck.rows.length > 0) {
        return res.status(409).json({ error: 'Username already taken' });
      }
    }

    // Build dynamic update query
    const updates = [];
    const args = [];

    if (newUsername) {
      updates.push('username = ?');
      args.push(newUsername);
    }

    if (newPassword) {
      updates.push('password = ?');
      args.push(newPassword);
    }

    if (newLicensePlate) {
      updates.push('liscense_plate = ?');
      args.push(newLicensePlate);
    }

    args.push(user.email);

    await db.execute({
      sql: `UPDATE accounts SET ${updates.join(', ')} WHERE email = ?`,
      args: args
    });

    // Generate new token with updated information
    const updatedResult = await db.execute({
      sql: 'SELECT * FROM accounts WHERE email = ?',
      args: [user.email]
    });

    const updatedUser = updatedResult.rows[0];
    const newToken = jwt.sign(
      {
        username: updatedUser.username,
        email: updatedUser.email,
        role: updatedUser.role,
        liscense_plate: updatedUser.liscense_plate,
        slot_index_taken: updatedUser.slot_index_taken,
        location_taken: updatedUser.location_taken
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.cookie('token', newToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      message: 'Account updated successfully',
      updated: {
        username: !!newUsername,
        password: !!newPassword,
        licensePlate: !!newLicensePlate
      }
    });
  } catch (err) {
    console.error('Error updating account:', err);
    res.status(500).json({ error: 'Failed to update account', details: err.message });
  }
});

// Get user data endpoint
app.get('/api/auth/user', async (req, res) => {
  const user = getUserFromToken(req);
  if (!user) return res.status(401).json({ error: 'Not logged in' });

  try {
    const result = await db.execute({
      sql: 'SELECT email, username, liscense_plate, role, location_index_admin FROM accounts WHERE email = ?',
      args: [user.email]
    });

    if (result.rows.length === 0)
      return res.status(404).json({ error: 'User not found' });

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

app.get('/test-email', async (req, res) => {
  try {
    const info = await transporter.sendMail({
      from: `"Parking Web Test" <${process.env.EMAIL_USER}>`,
      to: process.env.EMAIL_USER, // send to yourself first
      subject: '✅ Test Email from Parking Web',
      text: 'If you got this, your Gmail setup is working!',
    });

    console.log('Email sent:', info.messageId);
    res.send('✅ Test email sent successfully!');
  } catch (err) {
    console.error('❌ Email test failed:', err);
    res.status(500).send(`❌ Failed to send email: ${err.message}`);
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
      // 💡 FIX: Ensure floor is parsed as an integer for frontend consistency
      locationIndex: parseInt(row.location_index, 10),
      floor: parseInt(row.floor, 10),
      floorsImageIndex: row.floors_image_index
    }));

    // Log the data type being sent for verification
    if (maps.length > 0) {
      console.log(`[API Maps Success] Location ${locationId}: Found ${maps.length} maps. First floor type: ${typeof maps[0].floor}, Value: ${maps[0].floor}`);
    } else {
      console.log(`[API Maps Success] Location ${locationId}: Found 0 maps.`);
    }

    res.json(maps);
  } catch (err) {
    console.error('Error fetching maps:', err);
    res.status(500).json({ error: 'Failed to fetch maps', details: err.message });
  }
});
// -----------------------------------------------------------------------------
// API endpoint to get parking spaces for a specific location
app.get('/api/parking/:location_id', async (req, res) => {
  try {
    const locationId = req.params.location_id;
    const result = await db.execute({
      sql: 'SELECT * FROM parking_spaces WHERE location_index = ? ORDER BY "index" ASC',
      args: [locationId]
    });

    const spaces = result.rows.map(row => {
      // CRITICAL FIX: Use Number.isInteger to check if the value is a valid integer.
      // If the row.floor is non-numeric (NaN), default it to 0 or another known integer.
      const parsedFloor = parseInt(row.floor, 10);
      const floorValue = Number.isNaN(parsedFloor) ? 0 : parsedFloor;

      return {
        id: row.id,
        state: row.state,
        feature: row.exclusive,
        price: row.price,
        index: row.index,

        // Use the safely parsed floor value
        floor: floorValue,

        // Ensure other coordinates are also safely parsed
        locationIndex: parseInt(row.location_index, 10) || 0,
        locationX: parseInt(row.location_x, 10) || 0,
        locationY: parseInt(row.location_y, 10) || 0,
        sizeX: parseInt(row.width, 10) || 0,
        sizeY: parseInt(row.height, 10) || 0,
        plate: row.plate,
        daysToOccupy: row.days_to_occupy,
        lastUpdate: row.last_update,
        restrictionStart: row.restriction_start,
        restrictionEnd: row.restriction_end,
        restrictionFrequency: row.restriction_frequency
      };
    });

    // Log the new parsed value
    console.log('Rows found:', result.rows.length);
    if (spaces.length > 0) {
      console.log(`[API Parking Success - FIXED] Location ${locationId}: Found ${spaces.length} spaces. First floor type: ${typeof spaces[0].floor}, Value: ${spaces[0].floor}`);
    } else {
      console.log(`[API Parking Success] Location ${locationId}: Found 0 spaces.`);
    }

    res.json(spaces);
  } catch (err) {
    console.error('Error fetching parking spaces:', err);
    res.status(500).json({ error: 'Failed to fetch parking spaces', details: err.message });
  }
});

app.post('/api/parking/release', async (req, res) => {
  const { index } = req.body;

  const user = getUserFromToken(req);
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    const checkResult = await db.execute({
      sql: 'SELECT * FROM parking_spaces WHERE "index" = ?',
      args: [index]
    });

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Parking space not found' });
    }

    const row = checkResult.rows[0];

    if (row.plate !== user.liscense_plate) {
      return res.status(403).json({ error: 'You can only release your own parking space' });
    }

    await db.execute({
      sql: `UPDATE parking_spaces 
            SET state = ?, plate = NULL, days_to_occupy = 0, last_update = ? 
            WHERE "index" = ?`,
      args: ['available', new Date().toISOString(), index]
    });

    await db.execute({
      sql: `UPDATE accounts 
            SET slot_index_taken = NULL, location_taken = NULL 
            WHERE email = ?`,
      args: [user.email]
    });

    // Update location available slots
    await updateLocationAvailableSlots(row.location_index);

    res.json({ success: true, message: 'Parking space released' });
  } catch (err) {
    console.error('Error releasing parking space:', err);
    res.status(500).json({ error: 'Failed to release parking space', details: err.message });
  }
});

// API endpoint to reserve a parking space (updated to use 'index' column)
app.post('/api/parking/reserve', async (req, res) => {
  const { index, plate, days } = req.body;

  console.log('Reservation request:', { index, plate, days });

  const user = getUserFromToken(req);
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  if (!index || !plate || !days || days <= 0) {
    return res.status(400).json({ error: 'Invalid reservation data' });
  }

  const currentTime = new Date().toISOString();

  try {
    const checkResult = await db.execute({
      sql: 'SELECT * FROM parking_spaces WHERE "index" = ?',
      args: [index]
    });

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Parking space not found' });
    }

    const row = checkResult.rows[0];
    console.log('Found space:', row);

    const exclusive = row.exclusive?.toLowerCase() || 'normal';
    const role = user.role?.toLowerCase() || 'user';

    if (exclusive !== 'normal' && exclusive !== role) {
      return res.status(403).json({
        error: `Only ${exclusive.toUpperCase()} users can reserve this parking space`
      });
    }

    if (row.state !== 'available') {
      return res.status(400).json({ error: 'Parking space is not available' });
    }

    await db.execute({
      sql: `UPDATE parking_spaces 
            SET state = ?, plate = ?, days_to_occupy = ?, last_update = ? 
            WHERE "index" = ?`,
      args: ['taken', plate, days, currentTime, index]
    });

    await db.execute({
      sql: `UPDATE accounts 
            SET slot_index_taken = ?, location_taken = ? 
            WHERE email = ?`,
      args: [index, row.location_index, user.email]
    });

    // Update location available slots
    await updateLocationAvailableSlots(row.location_index);

    const updatedResult = await db.execute({
      sql: 'SELECT * FROM parking_spaces WHERE "index" = ?',
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

    console.log(`Reservation successful by ${user.role}:`, updatedSpace);
    res.json(updatedSpace);
  } catch (err) {
    console.error('Error during reservation:', err);
    res.status(500).json({ error: 'Failed to reserve parking space', details: err.message });
  }
});

async function updateLocationAvailableSlots(locationId) {
  try {
    const result = await db.execute({
      sql: 'SELECT COUNT(*) as count FROM parking_spaces WHERE location_index = ? AND state = ?',
      args: [locationId, 'available']
    });

    const availableCount = result.rows[0].count;

    await db.execute({
      sql: 'UPDATE locations SET current_available = ? WHERE id = ?',
      args: [availableCount, locationId]
    });

    console.log(`Updated location ${locationId}: ${availableCount} available slots`);
    return availableCount;
  } catch (err) {
    console.error('Error updating location slots:', err);
    throw err;
  }
}



app.get('/api/debug/all-tables', async (req, res) => {
  try {
    const locations = await db.execute('SELECT * FROM locations');
    const maps = await db.execute('SELECT * FROM maps');
    const parking = await db.execute('SELECT * FROM parking_spaces');

    res.json({
      locations: {
        count: locations.rows.length,
        data: locations.rows
      },
      maps: {
        count: maps.rows.length,
        data: maps.rows
      },
      parking_spaces: {
        count: parking.rows.length,
        data: parking.rows
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



// Export for Vercel
module.exports = app;

// Local (non-Vercel) server startup


app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
