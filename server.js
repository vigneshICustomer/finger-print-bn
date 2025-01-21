import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import pool from './db/connection.js';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Helper function to generate session ID
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

// Helper function to find existing identity
async function findExistingIdentity(visitorId, ip) {
  const result = await pool.query(
    `SELECT identity FROM identity_mappings 
     WHERE visitor_id = $1 
     OR ip_address = $2 
     ORDER BY created_at DESC 
     LIMIT 1`,
    [visitorId, ip]
  );
  return result.rows[0]?.identity || null;
}

// Initialize session
app.post('/api/init', async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const visitorId = crypto.randomBytes(16).toString('hex'); // Temporary until we implement server-side fingerprinting
    const sessionId = generateSessionId();

    // Check if this visitor/IP is already identified
    const identity = await findExistingIdentity(visitorId, ip);

    // Store session mapping
    await pool.query(
      'INSERT INTO session_mappings (session_id, visitor_id, ip_address) VALUES ($1, $2, $3)',
      [sessionId, visitorId, ip]
    );

    res.json({ sessionId, identity });
  } catch (err) {
    console.error('Error initializing session:', err);
    res.status(500).json({ error: 'Failed to initialize session' });
  }
});

// Track events
app.post('/api/track', async (req, res) => {
  const { sessionId, eventName, properties = {} } = req.body;
  
  try {
    // Get visitor details from session
    const sessionResult = await pool.query(
      'SELECT visitor_id, ip_address FROM session_mappings WHERE session_id = $1',
      [sessionId]
    );

    if (sessionResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid session' });
    }

    const { visitor_id, ip_address } = sessionResult.rows[0];
    
    // Check for existing identity
    const identity = await findExistingIdentity(visitor_id, ip_address);
    
    // Store event
    const result = await pool.query(
      `INSERT INTO events 
       (session_id, visitor_id, event_name, properties, identity, ip_address) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING *`,
      [sessionId, visitor_id, eventName, properties, identity, ip_address]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error tracking event:', err);
    res.status(500).json({ error: 'Failed to track event' });
  }
});

// Identify user
app.post('/api/identify', async (req, res) => {
  const { sessionId, userData } = req.body;
  
  try {
    // Get visitor details
    const sessionResult = await pool.query(
      'SELECT visitor_id, ip_address FROM session_mappings WHERE session_id = $1',
      [sessionId]
    );

    if (sessionResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid session' });
    }

    const { visitor_id, ip_address } = sessionResult.rows[0];
    
    // Begin transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      // Store in identity mappings - handle visitor_id conflict
      await client.query(
        `INSERT INTO identity_mappings (visitor_id, ip_address, identity)
         VALUES ($1, $2, $3)
         ON CONFLICT (visitor_id) 
         DO UPDATE SET identity = EXCLUDED.identity
         WHERE identity_mappings.visitor_id = EXCLUDED.visitor_id`,
        [visitor_id, ip_address, userData]
      );

      // Handle ip_address conflict separately
      await client.query(
        `INSERT INTO identity_mappings (visitor_id, ip_address, identity)
         VALUES ($1, $2, $3)
         ON CONFLICT (ip_address) 
         DO UPDATE SET identity = EXCLUDED.identity
         WHERE identity_mappings.ip_address = EXCLUDED.ip_address`,
        [visitor_id, ip_address, userData]
      );
      
      // Update all existing events
      await client.query(
        'UPDATE events SET identity = $1 WHERE visitor_id = $2 OR ip_address = $3',
        [userData, visitor_id, ip_address]
      );

      // Track identify event
      await client.query(
        `INSERT INTO events 
         (session_id, visitor_id, event_name, properties, identity, ip_address) 
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [sessionId, visitor_id, 'identify', userData, userData, ip_address]
      );
      
      await client.query('COMMIT');
      res.json({ success: true, identity: userData });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Error identifying user:', err);
    res.status(500).json({ error: 'Failed to identify user' });
  }
});

// Get all events for a session
app.get('/api/events/:sessionId', async (req, res) => {
  const { sessionId } = req.params;
  
  try {
    const result = await pool.query(
      'SELECT * FROM events WHERE session_id = $1 ORDER BY timestamp DESC',
      [sessionId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching events:', err);
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});