//logged by iyad

const express = require('express');
const path = require('path');
const session = require('express-session');
const { createClient } = require('@libsql/client');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Resend } = require('resend');
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

    // First check pending_verifications
    const verificationResult = await db.execute({
      sql: 'SELECT * FROM pending_verifications WHERE email = ? AND verified = 0',
      args: [userEmail]
    });

    if (verificationResult.rows.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Email verification not found or already verified'
      });
    }

    // Then get registration data
    const registrationResult = await db.execute({
      sql: 'SELECT * FROM pending_registrations WHERE email = ? AND verified = 0',
      args: [userEmail]
    });

    if (registrationResult.rows.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Registration data not found'
      });
    }

    const registration = registrationResult.rows[0];

    // Create the account
    await db.execute({
      sql: `INSERT INTO accounts 
            (username, email, password, role, liscense_plate, verified, slot_index_taken, location_taken) 
            VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)`,
      args: [
        registration.username,
        userEmail,
        registration.password,
        'user',
        registration.liscense_plate,
        true
      ]
    });

    // Mark both tables as verified
    await db.execute({
      sql: `UPDATE pending_verifications 
            SET verified = 1 
            WHERE email = ?`,
      args: [userEmail]
    });

    await db.execute({
      sql: `UPDATE pending_registrations 
            SET verified = 1, verified_at = CURRENT_TIMESTAMP 
            WHERE email = ?`,
      args: [userEmail]
    });

    console.log(`✅ Email verified and account created: ${userEmail}`);

    // Redirect to login with success message
    res.redirect('/login?verified=true');

  } catch (err) {
    console.error('Verification error:', err);
    res.status(400).json({
      success: false,
      error: 'Invalid or expired verification link'
    });
  }
});
// Initialize Resend client
const resend = new Resend(process.env.RESEND_API_KEY);

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

function parseDateInput(input) {
  const trimmed = input.trim();
  
  // Check for relative days: "2 days", "1 day"
  const daysMatch = trimmed.match(/^(\d+)\s*days?$/i);
  if (daysMatch) {
    const days = parseInt(daysMatch[1]);
    const date = new Date();
    date.setDate(date.getDate() + days);
    return date.toISOString().split('T')[0];
  }
  
  // Try parsing as absolute date
  const date = new Date(trimmed);
  if (!isNaN(date.getTime())) {
    return date.toISOString().split('T')[0];
  }
  
  return null;
}

/**
 * Calculate days between two dates
 */
function daysBetween(startDate, endDate) {
  const start = new Date(startDate);
  const end = new Date(endDate);
  const diffTime = Math.abs(end - start);
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  return diffDays;
}

/**
 * Check if two date ranges overlap
 */
function dateRangesOverlap(start1, end1, start2, end2) {
  const s1 = new Date(start1);
  const e1 = new Date(end1);
  const s2 = new Date(start2);
  const e2 = new Date(end2);
  
  return s1 <= e2 && s2 <= e1;
}


function getRestrictionRanges(restrictionJson, startDate, endDate) {
  if (!restrictionJson) return [];
  
  const ranges = [];
  
  try {
    const restrictions = JSON.parse(restrictionJson);
    const start = new Date(startDate);
    const end = new Date(endDate);
    
    // Iterate through each day in the requested range
    for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
      const currentDate = new Date(d);
      const currentMonth = currentDate.getMonth() + 1;
      const currentDay = currentDate.getDate();
      const currentDayOfWeek = currentDate.getDay();
      const year = currentDate.getFullYear();
      
      let isRestricted = false;
      
      // Check yearly restrictions
      if (restrictions.yearly) {
        const monthDay = `${currentMonth}-${currentDay}`;
        if (restrictions.yearly[monthDay]) {
          isRestricted = true;
        }
      }
      
      // Check weekly restrictions
      if (restrictions.weekly && restrictions.weekly[currentDayOfWeek]) {
        isRestricted = true;
      }
      
      // Check daily restrictions
      if (restrictions.daily) {
        isRestricted = true;
      }
      
      // Check special restrictions
      if (restrictions.special?.daily) {
        const dateStr = `${year}-${String(currentMonth).padStart(2, '0')}-${String(currentDay).padStart(2, '0')}`;
        if (restrictions.special.daily[dateStr]) {
          isRestricted = true;
        }
      }
      
      if (isRestricted) {
        ranges.push({
          start: currentDate.toISOString().split('T')[0],
          end: currentDate.toISOString().split('T')[0],
          type: 'restriction'
        });
      }
    }
  } catch (err) {
    console.error('Error parsing restriction_json:', err);
  }
  
  return ranges;
}

/**
 * Get all occupancy date ranges from occupancy_json
 */
function getOccupancyRanges(occupancyJson) {
  if (!occupancyJson) return [];
  
  try {
    const occupancies = JSON.parse(occupancyJson);
    if (!Array.isArray(occupancies)) return [];
    
    return occupancies.map(occ => ({
      start: occ.startDate,
      end: occ.endDate,
      type: 'occupancy',
      plate: occ.plate,
      username: occ.username
    }));
  } catch (err) {
    console.error('Error parsing occupancy_json:', err);
    return [];
  }
}

// GET endpoint: Fetch calendar data for a parking space
app.get('/api/parking/calendar/:index', async (req, res) => {
  const user = getUserFromToken(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  
  const spaceIndex = req.params.index;
  const startDate = req.query.start || new Date().toISOString().split('T')[0];
  const endDate = req.query.end || new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
  
  try {
    const result = await db.execute({
      sql: 'SELECT * FROM parking_spaces WHERE "index" = ?',
      args: [spaceIndex]
    });
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Parking space not found' });
    }
    
    const space = result.rows[0];
    
    const restrictions = getRestrictionRanges(space.restriction_json, startDate, endDate);
    const occupancies = getOccupancyRanges(space.occupancy_json);
    
    res.json({
      spaceIndex: space.index,
      price: space.price,
      restrictions: restrictions,
      occupancies: occupancies,
      events: [
        ...restrictions.map(r => ({
          title: 'Restricted',
          start: r.start,
          end: r.end,
          color: '#dc3545',
          textColor: 'white',
          type: 'restriction'
        })),
        ...occupancies.map(o => ({
          title: `Occupied by ${o.username}`,
          start: o.start,
          end: o.end,
          color: '#ffc107',
          textColor: 'black',
          type: 'occupancy',
          extendedProps: {
            plate: o.plate,
            username: o.username
          }
        }))
      ]
    });
  } catch (err) {
    console.error('Error fetching calendar data:', err);
    res.status(500).json({ error: 'Failed to fetch calendar data', details: err.message });
  }
});

app.post('/api/parking/reserve-calendar', async (req, res) => {
  const user = getUserFromToken(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  
  const { index, startDate, endDate } = req.body;
  
  if (!index || !startDate || !endDate) {
    return res.status(400).json({ error: 'Missing required fields: index, startDate, endDate' });
  }
  
  // Parse and validate dates
  const parsedStart = parseDateInput(startDate);
  const parsedEnd = parseDateInput(endDate);
  
  if (!parsedStart || !parsedEnd) {
    return res.status(400).json({ error: 'Invalid date format' });
  }
  
  const start = new Date(parsedStart);
  const end = new Date(parsedEnd);
  
  if (start >= end) {
    return res.status(400).json({ error: 'End date must be after start date' });
  }
  
  if (start < new Date(new Date().toISOString().split('T')[0])) {
    return res.status(400).json({ error: 'Cannot book dates in the past' });
  }
  
  const days = daysBetween(parsedStart, parsedEnd);
  const clampedDays = Math.max(1, days); // Clamp minimum to 1 day
  
  try {
    const result = await db.execute({
      sql: 'SELECT * FROM parking_spaces WHERE "index" = ?',
      args: [index]
    });
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Parking space not found' });
    }
    
    const space = result.rows[0];
    
    // Check for restriction overlaps
    const restrictions = getRestrictionRanges(space.restriction_json, parsedStart, parsedEnd);
    if (restrictions.length > 0) {
      return res.status(409).json({
        error: 'Selected dates overlap with restricted periods',
        overlaps: restrictions
      });
    }
    
    // Check for occupancy overlaps
    const existingOccupancies = getOccupancyRanges(space.occupancy_json);
    const hasOverlap = existingOccupancies.some(occ => 
      dateRangesOverlap(parsedStart, parsedEnd, occ.start, occ.end)
    );
    
    if (hasOverlap) {
      return res.status(409).json({
        error: 'Selected dates overlap with existing reservations',
        overlaps: existingOccupancies.filter(occ => 
          dateRangesOverlap(parsedStart, parsedEnd, occ.start, occ.end)
        )
      });
    }
    
    // Check exclusive space permissions
    const exclusive = space.exclusive?.toLowerCase() || 'normal';
    const role = user.role?.toLowerCase() || 'user';
    
    if (exclusive !== 'normal' && exclusive !== role) {
      return res.status(403).json({
        error: `Only ${exclusive.toUpperCase()} users can reserve this parking space`
      });
    }
    
    // Create new occupancy entry
    const newOccupancy = {
      username: user.username,
      plate: user.liscense_plate,
      startDate: parsedStart,
      endDate: parsedEnd,
      createdAt: new Date().toISOString()
    };
    
    // Update occupancy_json
    let occupancies = [];
    if (space.occupancy_json) {
      try {
        occupancies = JSON.parse(space.occupancy_json);
        if (!Array.isArray(occupancies)) occupancies = [];
      } catch (e) {
        occupancies = [];
      }
    }
    
    occupancies.push(newOccupancy);
    const updatedOccupancyJson = JSON.stringify(occupancies);
    
    // Calculate total price
    const totalPrice = parseFloat(space.price) * clampedDays;
    
    // Update parking space
    await db.execute({
      sql: `UPDATE parking_spaces 
            SET occupancy_json = ?, 
                state = ?, 
                plate = ?, 
                days_to_occupy = ?, 
                last_update = ? 
            WHERE "index" = ?`,
      args: [updatedOccupancyJson, 'taken', user.liscense_plate, clampedDays, new Date().toISOString(), index]
    });
    
    // Update user account
    await db.execute({
      sql: `UPDATE accounts 
            SET slot_index_taken = ?, location_taken = ? 
            WHERE email = ?`,
      args: [index, space.location_index, user.email]
    });
    
    await updateLocationAvailableSlots(space.location_index);
    
    console.log(`Calendar reservation successful: ${user.username} reserved space ${index} from ${parsedStart} to ${parsedEnd}`);
    
    res.json({
      success: true,
      reservation: {
        spaceIndex: index,
        startDate: parsedStart,
        endDate: parsedEnd,
        days: clampedDays,
        totalPrice: totalPrice.toFixed(2),
        username: user.username,
        plate: user.liscense_plate
      }
    });
  } catch (err) {
    console.error('Error creating calendar reservation:', err);
    res.status(500).json({ error: 'Failed to create reservation', details: err.message });
  }
});

// PUT endpoint: Admin update occupancy_json
app.put('/api/admin/parking/:index/occupancy', async (req, res) => {
  const user = getUserFromToken(req);
  if (!user || user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin privileges required' });
  }
  
  const { index } = req.params;
  const { occupancy_json } = req.body;
  
  try {
    // Validate JSON
    const parsed = JSON.parse(occupancy_json);
    if (!Array.isArray(parsed)) {
      return res.status(400).json({ error: 'occupancy_json must be an array' });
    }
    
    await db.execute({
      sql: 'UPDATE parking_spaces SET occupancy_json = ? WHERE "index" = ?',
      args: [occupancy_json, index]
    });
    
    res.json({ success: true, message: 'Occupancy updated successfully' });
  } catch (err) {
    console.error('Error updating occupancy:', err);
    res.status(500).json({ error: 'Failed to update occupancy', details: err.message });
  }
});

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

app.get('/home-logout', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home-logout.html'));
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

app.post('/api/parking/cancel-calendar', async (req, res) => {
  const user = getUserFromToken(req);
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const { index } = req.body;
  if (!index) {
    return res.status(400).json({ error: 'Missing required field: index' });
  }

  try {
    // Get parking space data
    const result = await db.execute({
      sql: 'SELECT * FROM parking_spaces WHERE "index" = ?',
      args: [index]
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Parking space not found' });
    }

    const space = result.rows[0];
    let occupancies = [];

    // Parse existing occupancies
    if (space.occupancy_json) {
      try {
        occupancies = JSON.parse(space.occupancy_json);
        if (!Array.isArray(occupancies)) occupancies = [];
      } catch (e) {
        console.error('Error parsing occupancy_json:', e);
        occupancies = [];
      }
    }

    // Filter out user's reservations
    const updatedOccupancies = occupancies.filter(occ => 
      occ.username !== user.username && occ.plate !== user.liscense_plate
    );

    // If no changes were made, user didn't have a reservation
    if (occupancies.length === updatedOccupancies.length) {
      return res.status(404).json({ error: 'No reservation found for this user' });
    }

    // Update parking space state if no remaining occupancies
    const newState = updatedOccupancies.length === 0 ? 'available' : 'taken';
    const updatedOccupancyJson = JSON.stringify(updatedOccupancies);

    // Update parking space
    await db.execute({
      sql: `UPDATE parking_spaces 
            SET occupancy_json = ?, 
                state = ?,
                plate = CASE WHEN ? = 'available' THEN NULL ELSE plate END,
                days_to_occupy = CASE WHEN ? = 'available' THEN 0 ELSE days_to_occupy END,
                last_update = ? 
            WHERE "index" = ?`,
      args: [
        updatedOccupancyJson, 
        newState,
        newState,
        newState,
        new Date().toISOString(),
        index
      ]
    });

    // Clear user's parking assignment if they have no other reservations
    await db.execute({
      sql: `UPDATE accounts 
            SET slot_index_taken = CASE 
                WHEN email = ? AND slot_index_taken = ? THEN NULL 
                ELSE slot_index_taken END,
                location_taken = CASE 
                WHEN email = ? AND slot_index_taken = ? THEN NULL 
                ELSE location_taken END
            WHERE email = ?`,
      args: [user.email, index, user.email, index, user.email]
    });

    // Update location available slots
    await updateLocationAvailableSlots(space.location_index);

    console.log(`Calendar reservation canceled: User ${user.username} canceled space ${index}`);

    res.json({
      success: true,
      message: 'Reservation canceled successfully'
    });

  } catch (err) {
    console.error('Error canceling calendar reservation:', err);
    res.status(500).json({ 
      error: 'Failed to cancel reservation', 
      details: err.message 
    });
  }
});


// ...existing code...
app.get('/api/locations', async (req, res) => {
  try {
    // Fetch all locations
    const locationsResult = await db.execute('SELECT * FROM locations');
    const locations = locationsResult.rows;

    // Fetch available counts grouped by location_index in one query
    const countsResult = await db.execute({
      sql: `SELECT location_index, COUNT(*) as available_count
            FROM parking_spaces
            WHERE state = ?
            GROUP BY location_index`,
      args: ['available']
    });

    // Build a map of location_index -> available_count
    const countsMap = {};
    countsResult.rows.forEach(row => {
      // ensure numeric type
      countsMap[String(row.location_index)] = Number(row.available_count) || 0;
    });

    // Merge counts into locations response
    const response = locations.map(row => ({
      id: row.id,
      imageIndex: row.image_index,
      // live count based on parking_spaces state === 'available'
      currentAvailable: countsMap[String(row.id)] || 0,
      addressLocation: row.adress_location,
      averagePrice: row.avarage_price,
      redirect: '/map'
    }));

    res.json(response);
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

// Replace the /api/admin/overdue/:location_id endpoint with this fixed version:

app.get('/api/admin/overdue/:location_id', async (req, res) => {
  const user = getUserFromToken(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });

  const locationId = req.params.location_id;

  if (user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin privileges required' });
  }
  if (user.location_index_admin && parseInt(user.location_index_admin) !== parseInt(locationId)) {
    return res.status(403).json({ error: 'Admin does not manage this location' });
  }

  try {
    // Fixed: Remove 'id' column which doesn't exist in parking_spaces table
    const result = await db.execute({
      sql: `
        SELECT
          "index",
          location_index,
          state,
          is_occupied,
          plate,
          days_to_occupy,
          last_update,
          datetime(last_update, '+' || days_to_occupy || ' days') AS expiry,
          location_x,
          location_y,
          width,
          height,
          floor,
          price,
          exclusive,
          restriction_json
        FROM parking_spaces
        WHERE location_index = ?
          AND (is_occupied = 1 OR state != 'available')
          AND days_to_occupy IS NOT NULL
          AND days_to_occupy > 0
          AND datetime(last_update, '+' || days_to_occupy || ' days') <= datetime('now')
        ORDER BY expiry ASC
      `,
      args: [locationId]
    });

    const overdue = (result.rows || []).map(row => {
      const mapped = {
        index: row.index, // Use index as the unique identifier
        locationIndex: row.location_index,
        state: row.state,
        isOccupied: !!row.is_occupied,
        plate: row.plate,
        daysToOccupy: row.days_to_occupy,
        lastUpdate: row.last_update,
        expiry: row.expiry,
        floor: row.floor,
        locationX: row.location_x,
        locationY: row.location_y,
        sizeX: row.width,
        sizeY: row.height,
        exclusive: row.exclusive,
        price: row.price,
        restrictionJson: row.restriction_json
      };

      // Log each overdue space to the terminal
      try {
        const nowIso = new Date().toISOString();
        console.log(`[OVERDUE] ${nowIso} location=${locationId} space_index=${mapped.index} plate=${mapped.plate || 'N/A'} last_update=${mapped.lastUpdate} expiry=${mapped.expiry}`);
      } catch (e) {
        console.log('[OVERDUE] (failed to format log) location=', locationId, 'space_index=', mapped.index);
      }

      return mapped;
    });

    res.json(overdue);
  } catch (err) {
    console.error('Error fetching overdue parking spaces:', err);
    res.status(500).json({ error: 'Failed to fetch overdue list', details: err.message });
  }
});

// Logout endpoint
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});





// Updated Register endpoint with automatic verification email using Resend
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, liscense_plate } = req.body;
  if (!username || !email || !password || !liscense_plate) {
    return res.status(400).json({ error: 'All fields required' });
  }

  try {
    // Check if user already exists
    const existing = await db.execute({
      sql: 'SELECT * FROM accounts WHERE email = ? OR username = ?',
      args: [email, username]
    });

    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Email or username already exists' });
    }

    // Create both required tables
    await db.execute(`
  CREATE TABLE IF NOT EXISTS pending_verifications (
    email TEXT PRIMARY KEY,
    verified INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

await db.execute(`
  CREATE TABLE IF NOT EXISTS pending_registrations (
    email TEXT PRIMARY KEY,
    username TEXT,
    password TEXT,
    liscense_plate TEXT,
    verified INTEGER DEFAULT 0,
    verified_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);


    // Add email to pending_verifications (unverified)
    await db.execute({
      sql: `INSERT INTO pending_verifications (email, verified) 
            VALUES (?, 0)
            ON CONFLICT(email) DO UPDATE SET verified = 0`,
      args: [email]
    });

    // Store registration data
    await db.execute({
      sql: `
        INSERT INTO pending_registrations 
        (email, username, password, liscense_plate, verified) 
        VALUES (?, ?, ?, ?, 0)
        ON CONFLICT(email) DO UPDATE SET
          username = excluded.username,
          password = excluded.password,
          liscense_plate = excluded.liscense_plate,
          verified = 0
      `,
      args: [email, username, password, liscense_plate]
    });

    // Generate verification token
    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '24h' });
    const verificationLink = `${BASE_URL}/api/auth/verify/${encodeURIComponent(token)}`;

    // Send verification email
    try {
      const { data, error } = await resend.emails.send({
        from: 'Master Parker <noreply@group5masterparker.shop>',
        to: [email],
        subject: 'Verify your email address',
        html: `
          <h2>Verify your email address</h2>
          <p>Click below to verify this email and complete your registration:</p>
          <p><a href="${verificationLink}" target="_blank">${verificationLink}</a></p>
          <p>If you didn't request this, please ignore it.</p>
        `
      });

      if (error) {
        console.error('❌ Failed to send verification email:', error);
        return res.status(500).json({
          error: 'Failed to send verification email',
          details: error.message
        });
      }

      console.log('📧 Verification email sent to:', email, 'Message ID:', data?.id);
      
    } catch (emailErr) {
      console.error('❌ Failed to send verification email:', emailErr);
      return res.status(500).json({
        error: 'Failed to send verification email',
        details: emailErr.message
      });
    }

    res.json({
      success: true,
      message: 'Please check your email to verify your account'
    });

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
    const { data, error } = await resend.emails.send({
      from: 'Master Parker <noreply@group5masterparker.shop>',
      to: [process.env.EMAIL_USER || 'test@example.com'],
      subject: '✅ Test Email from Parking Web',
      text: 'If you got this, your Resend setup is working!',
      html: '<p>If you got this, your <strong>Resend</strong> setup is working!</p>'
    });

    if (error) {
      console.error('❌ Email test failed:', error);
      return res.status(500).send(`❌ Failed to send email: ${error.message}`);
    }

    console.log('Email sent successfully:', data);
    res.send(`✅ Test email sent successfully! Message ID: ${data?.id}`);
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
      hasSessionSecret: !!process.env.SESSION_SECRET,
      hasResendKey: !!process.env.RESEND_API_KEY
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


/**
 * Check if a parking space is currently restricted based on restriction_json
 * @param {string} restrictionJson - JSON string containing restriction rules
 * @returns {boolean} - true if restricted, false if available
 */
function isSpaceRestricted(restrictionJson) {
  if (!restrictionJson) return false;
  
  try {
    const restrictions = JSON.parse(restrictionJson);
    const now = new Date();
    
    // Get current time components
    const currentMonth = now.getMonth() + 1; // 1-12
    const currentDay = now.getDate(); // 1-31
    const currentDayOfWeek = now.getDay(); // 0=Sunday, 6=Saturday
    const currentTime = now.toTimeString().slice(0, 5); // "HH:MM"
    
    // Check yearly restrictions (specific dates like Christmas)
    if (restrictions.yearly && typeof restrictions.yearly === 'object') {
      for (const [monthDay, timeRanges] of Object.entries(restrictions.yearly)) {
        // Format: "12-25" for December 25th
        const [month, day] = monthDay.split('-').map(Number);
        if (currentMonth === month && currentDay === day) {
          if (isTimeRestricted(timeRanges, currentTime)) {
            return true;
          }
        }
      }
    }
    
    // Check weekly restrictions (days of week)
    if (restrictions.weekly && typeof restrictions.weekly === 'object') {
      for (const [dayOfWeek, timeRanges] of Object.entries(restrictions.weekly)) {
        // 0=Sunday, 1=Monday, ..., 6=Saturday
        if (currentDayOfWeek === parseInt(dayOfWeek)) {
          if (isTimeRestricted(timeRanges, currentTime)) {
            return true;
          }
        }
      }
    }
    
    // Check daily restrictions (applies every day)
    if (restrictions.daily && typeof restrictions.daily === 'object') {
      if (isTimeRestricted(restrictions.daily, currentTime)) {
        return true;
      }
    }
    
    // Check special restrictions (specific dates with daily patterns)
    if (restrictions.special && restrictions.special.daily && typeof restrictions.special.daily === 'object') {
      for (const [dateStr, timeRanges] of Object.entries(restrictions.special.daily)) {
        // Format: "2025-12-25" for specific date
        const [year, month, day] = dateStr.split('-').map(Number);
        if (now.getFullYear() === year && currentMonth === month && currentDay === day) {
          if (isTimeRestricted(timeRanges, currentTime)) {
            return true;
          }
        }
      }
    }
    
    return false;
  } catch (err) {
    console.error('Error parsing restriction_json:', err);
    return false;
  }
}

/**
 * Check if current time falls within restricted time ranges
 * @param {object|array} timeRanges - Object or array of time ranges
 * @param {string} currentTime - Current time in "HH:MM" format
 * @returns {boolean} - true if time is restricted
 */
function isTimeRestricted(timeRanges, currentTime) {
  // Handle array of time ranges: ["09:00-17:00", "19:00-22:00"]
  if (Array.isArray(timeRanges)) {
    return timeRanges.some(range => isTimeInRange(range, currentTime));
  }
  
  // Handle object with time ranges: { "09:00-17:00": true, "19:00-22:00": true }
  if (typeof timeRanges === 'object') {
    return Object.keys(timeRanges).some(range => isTimeInRange(range, currentTime));
  }
  
  // Handle single string: "09:00-17:00"
  if (typeof timeRanges === 'string') {
    return isTimeInRange(timeRanges, currentTime);
  }
  
  return false;
}

/**
 * Check if a time falls within a time range
 * @param {string} range - Time range in format "HH:MM-HH:MM"
 * @param {string} time - Time to check in "HH:MM" format
 * @returns {boolean}
 */
function isTimeInRange(range, time) {
  const [start, end] = range.split('-');
  if (!start || !end) return false;
  
  // Convert to minutes for easier comparison
  const timeInMinutes = timeToMinutes(time);
  const startInMinutes = timeToMinutes(start);
  const endInMinutes = timeToMinutes(end);
  
  // Handle ranges that cross midnight
  if (endInMinutes < startInMinutes) {
    return timeInMinutes >= startInMinutes || timeInMinutes <= endInMinutes;
  }
  
  return timeInMinutes >= startInMinutes && timeInMinutes <= endInMinutes;
}

/**
 * Convert time string to minutes since midnight
 * @param {string} time - Time in "HH:MM" format
 * @returns {number}
 */
function timeToMinutes(time) {
  const [hours, minutes] = time.split(':').map(Number);
  return hours * 60 + minutes;
}

// REPLACE the existing /api/parking/:location_id endpoint with this updated version:
app.get('/api/parking/:location_id', async (req, res) => {
  try {
    const locationId = req.params.location_id;
    const result = await db.execute({
      sql: 'SELECT * FROM parking_spaces WHERE location_index = ? ORDER BY "index" ASC',
      args: [locationId]
    });

    const spaces = result.rows.map(row => {
      const parsedFloor = parseInt(row.floor, 10);
      const floorValue = Number.isNaN(parsedFloor) ? 0 : parsedFloor;
      
      // Check if space is currently restricted
      const isRestricted = isSpaceRestricted(row.restriction_json);
      
      // If restricted and currently available, mark as restricted
      let effectiveState = row.state;
      if (isRestricted && row.state === 'available') {
        effectiveState = 'restricted';
      }

      return {
        id: row.id,
        state: effectiveState,
        originalState: row.state,
        feature: row.exclusive,
        price: row.price,
        index: row.index,
        floor: floorValue,
        locationIndex: parseInt(row.location_index, 10) || 0,
        locationX: parseInt(row.location_x, 10) || 0,
        locationY: parseInt(row.location_y, 10) || 0,
        sizeX: parseInt(row.width, 10) || 0,
        sizeY: parseInt(row.height, 10) || 0,
        plate: row.plate,
        daysToOccupy: row.days_to_occupy,
        lastUpdate: row.last_update,
        restrictionJson: row.restriction_json,
        isRestricted: isRestricted
      };
    });

    console.log('Rows found:', result.rows.length);
    if (spaces.length > 0) {
      const restrictedCount = spaces.filter(s => s.isRestricted).length;
      console.log(`[API Parking Success] Location ${locationId}: Found ${spaces.length} spaces (${restrictedCount} currently restricted)`);
    }

    res.json(spaces);
  } catch (err) {
    console.error('Error fetching parking spaces:', err);
    res.status(500).json({ error: 'Failed to fetch parking spaces', details: err.message });
  }
});

// UPDATE the /api/parking/reserve endpoint to check restrictions:
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

    // Check if space is currently restricted
    if (isSpaceRestricted(row.restriction_json)) {
      return res.status(403).json({ 
        error: 'This parking space is currently restricted and cannot be reserved at this time' 
      });
    }

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
      restrictionJson: updatedRow.restriction_json
    };

    console.log(`Reservation successful by ${user.role}:`, updatedSpace);
    res.json(updatedSpace);
  } catch (err) {
    console.error('Error during reservation:', err);
    res.status(500).json({ error: 'Failed to reserve parking space', details: err.message });
  }
});

// UPDATE: Modify the admin parking update endpoint to handle restriction_json


// ADD: New endpoint to validate restriction JSON format
app.post('/api/admin/parking/validate-restrictions', async (req, res) => {
  const user = getUserFromToken(req);
  if (!user || user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin privileges required' });
  }

  const { restriction_json } = req.body;

  try {
    const restrictions = JSON.parse(restriction_json);
    
    // Validate structure
    const validKeys = ['yearly', 'weekly', 'daily', 'special'];
    const providedKeys = Object.keys(restrictions);
    const invalidKeys = providedKeys.filter(k => !validKeys.includes(k));
    
    if (invalidKeys.length > 0) {
      return res.status(400).json({ 
        valid: false, 
        error: `Invalid keys: ${invalidKeys.join(', ')}. Valid keys are: ${validKeys.join(', ')}` 
      });
    }

    res.json({ 
      valid: true, 
      message: 'Restriction JSON is valid',
      preview: getRestrictionPreview(restrictions)
    });
  } catch (err) {
    res.status(400).json({ 
      valid: false, 
      error: 'Invalid JSON format', 
      details: err.message 
    });
  }
});

/**
 * Generate a human-readable preview of restrictions
 */
function getRestrictionPreview(restrictions) {
  const preview = [];
  
  if (restrictions.yearly) {
    Object.entries(restrictions.yearly).forEach(([date, times]) => {
      const [month, day] = date.split('-');
      preview.push(`Yearly on ${month}/${day}: ${JSON.stringify(times)}`);
    });
  }
  
  if (restrictions.weekly) {
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    Object.entries(restrictions.weekly).forEach(([dayNum, times]) => {
      preview.push(`Every ${days[dayNum]}: ${JSON.stringify(times)}`);
    });
  }
  
  if (restrictions.daily) {
    preview.push(`Daily: ${JSON.stringify(restrictions.daily)}`);
  }
  
  if (restrictions.special?.daily) {
    Object.entries(restrictions.special.daily).forEach(([date, times]) => {
      preview.push(`Special date ${date}: ${JSON.stringify(times)}`);
    });
  }
  
  return preview;
}


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