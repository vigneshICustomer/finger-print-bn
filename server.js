import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { pool, getClient } from './db/connection.js';
import { getVisitorData, verifyVisitorId } from './services/fingerprint.js';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Helper function to generate session ID
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

// Helper function to find existing identity with confidence scoring
async function findExistingIdentity(tenantId, visitorId, ip, browserDetails) {
  const client = await getClient();
  try {
    // First try to find exact fingerprint match
    const fingerprintMatch = await client.query(
      `SELECT identity, confidence_score, identification_method, browser_details 
       FROM ${tenantId}.identity_mappings 
       WHERE visitor_id = $1 
       ORDER BY last_seen_at DESC 
       LIMIT 1`,
      [visitorId]
    );

    if (fingerprintMatch.rows[0]) {
      return {
        ...fingerprintMatch.rows[0],
        matchType: 'fingerprint',
        confidence: Math.max(fingerprintMatch.rows[0].confidence_score || 0.8, 0.8) // High confidence for fingerprint matches
      };
    }

    // Then try IP match with browser fingerprint correlation
    const ipMatches = await client.query(
      `SELECT identity, confidence_score, identification_method, browser_details 
       FROM ${tenantId}.identity_mappings 
       WHERE ip_address = $1 
       ORDER BY last_seen_at DESC`,
      [ip]
    );

    if (ipMatches.rows.length > 0) {
      // If we have browser details, try to correlate them
      if (browserDetails) {
        for (const match of ipMatches.rows) {
          if (match.browser_details && 
              match.browser_details.browserName === browserDetails.browserName &&
              match.browser_details.os === browserDetails.os) {
            return {
              ...match,
              matchType: 'ip_browser',
              confidence: Math.max(match.confidence_score || 0.6, 0.6) // Medium-high confidence for IP + browser match
            };
          }
        }
      }

      // Return the most recent IP match if no browser match found
      return {
        ...ipMatches.rows[0],
        matchType: 'ip',
        confidence: Math.max(ipMatches.rows[0].confidence_score || 0.4, 0.4) // Medium confidence for IP-only match
      };
    }

    return null;
  } catch (error) {
    console.error('Error finding existing identity:', error);
    return null;
  } finally {
    client.release();
  }
}

// Initialize session
app.post('/eventTracking/init', async (req, res) => {
  try {
    const { requestId, visitorId, tenantId } = req.body;
    
    if (!requestId || !visitorId || !tenantId) {
      return res.status(400).json({ error: 'requestId, visitorId, and tenantId are required' });
    }

    // Get verified visitor data from FingerprintJS Pro
    const visitorData = await getVisitorData(requestId);
    
    // Verify the claimed visitor ID matches the one from FingerprintJS Pro
    if (visitorData.visitorId !== visitorId) {
      return res.status(403).json({ error: 'Invalid visitor ID' });
    }

    const sessionId = generateSessionId();

    // Check if this visitor/IP is already identified
    const identityMatch = await findExistingIdentity(
      tenantId,
      visitorData.visitorId, 
      visitorData.ip,
      visitorData.browserDetails
    );

    // Get database client
    const client = await getClient();
    try {
      await client.query('BEGIN');

      // Create tables if they don't exist
      await client.query(`
        CREATE TABLE IF NOT EXISTS ${tenantId}.identity_mappings (
          id SERIAL PRIMARY KEY,
          visitor_id TEXT UNIQUE,
          ip_address TEXT,
          browser_details JSONB,
          confidence_score FLOAT,
          first_seen_at TIMESTAMP WITH TIME ZONE,
          last_seen_at TIMESTAMP WITH TIME ZONE,
          geolocation JSONB,
          asn JSONB,
          identification_method TEXT,
          identity JSONB
        );

        CREATE TABLE IF NOT EXISTS ${tenantId}.session_mappings (
          id SERIAL PRIMARY KEY,
          session_id TEXT UNIQUE,
          visitor_id TEXT,
          ip_address TEXT,
          browser_details JSONB,
          confidence_score FLOAT,
          identification_method TEXT
        );

        CREATE TABLE IF NOT EXISTS ${tenantId}.events (
          id SERIAL PRIMARY KEY,
          session_id TEXT,
          visitor_id TEXT,
          event_name TEXT,
          properties JSONB,
          identity JSONB,
          ip_address TEXT,
          browser_details JSONB,
          confidence_score FLOAT,
          identification_method TEXT,
          geolocation JSONB,
          asn JSONB,
          first_seen_at TIMESTAMP WITH TIME ZONE,
          last_seen_at TIMESTAMP WITH TIME ZONE,
          timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Update or insert identity mapping
      await client.query(
        `INSERT INTO ${tenantId}.identity_mappings 
         (visitor_id, ip_address, browser_details, confidence_score, 
          first_seen_at, last_seen_at, geolocation, asn, identification_method, identity)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (visitor_id) 
         DO UPDATE SET 
           ip_address = EXCLUDED.ip_address,
           browser_details = EXCLUDED.browser_details,
           confidence_score = EXCLUDED.confidence_score,
           last_seen_at = EXCLUDED.last_seen_at,
           geolocation = EXCLUDED.geolocation,
           asn = EXCLUDED.asn,
           identification_method = EXCLUDED.identification_method,
           identity = COALESCE(identity_mappings.identity, EXCLUDED.identity)
         RETURNING *`,
        [
          visitorData.visitorId,
          visitorData.ip,
          visitorData.browserDetails,
          visitorData.confidence?.score || 1.0,
          visitorData.firstSeenAt?.global || new Date(),
          visitorData.lastSeenAt?.global || new Date(),
          visitorData.geolocation,
          visitorData.asn,
          'fingerprint',
          identityMatch?.identity
        ]
      );

      // Store session mapping with verified data
      await client.query(
        `INSERT INTO ${tenantId}.session_mappings 
         (session_id, visitor_id, ip_address, browser_details, 
          confidence_score, identification_method)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          sessionId,
          visitorData.visitorId,
          visitorData.ip,
          visitorData.browserDetails,
          visitorData.confidence?.score || 1.0,
          'fingerprint'
        ]
      );

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    res.json({ 
      sessionId, 
      identity: identityMatch?.identity || null,
      identityMatch: {
        type: identityMatch?.matchType || 'new_visitor',
        confidence: identityMatch?.confidence || 1.0
      },
      visitorData: {
        visitorId: visitorData.visitorId,
        browserDetails: visitorData.browserDetails,
        device: visitorData.device,
        os: visitorData.os,
        geolocation: visitorData.geolocation,
        firstSeen: visitorData.firstSeenAt,
        lastSeen: visitorData.lastSeenAt
      }
    });
  } catch (err) {
    console.error('Error initializing session:', err);
    res.status(500).json({ error: 'Failed to initialize session' });
  }
});

// Track events
app.post('/eventTracking/track', async (req, res) => {
  const { sessionId, eventName, properties = {}, requestId, visitorId, tenantId } = req.body;
  
  if (!tenantId) {
    return res.status(400).json({ error: 'tenantId is required' });
  }
  
  try {
    // Get database client
    const client = await getClient();
    
    // Get visitor details from session
    const sessionResult = await client.query(
      `SELECT visitor_id, ip_address, browser_details, 
              confidence_score, identification_method 
       FROM ${tenantId}.session_mappings 
       WHERE session_id = $1`,
      [sessionId]
    );

    if (sessionResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid session' });
    }

    const session = sessionResult.rows[0];

    // Verify visitor ID if provided
    if (requestId && visitorId) {
      const isValid = await verifyVisitorId(requestId, visitorId);
      if (!isValid) {
        return res.status(403).json({ error: 'Invalid visitor ID' });
      }
    }
    
    // Check for existing identity
    const identityMatch = await findExistingIdentity(
      tenantId,
      session.visitor_id, 
      session.ip_address,
      session.browser_details
    );
    
    // Get the latest geolocation data
    const geoResult = await client.query(
      `SELECT geolocation, asn FROM ${tenantId}.identity_mappings 
       WHERE visitor_id = $1 
       ORDER BY last_seen_at DESC 
       LIMIT 1`,
      [session.visitor_id]
    );

    const geoData = geoResult.rows[0] || {};

    // Store event with all available context including geolocation
    const result = await client.query(
      `INSERT INTO ${tenantId}.events 
       (session_id, visitor_id, event_name, properties, identity, 
        ip_address, browser_details, confidence_score, 
        identification_method, geolocation) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
       RETURNING *`,
      [
        sessionId,
        session.visitor_id,
        eventName,
        properties,
        identityMatch?.identity,
        session.ip_address,
        session.browser_details,
        identityMatch?.confidence || session.confidence_score,
        session.identification_method,
        geoData.geolocation
      ]
    );

    res.json({
      ...result.rows[0],
      identityMatch: identityMatch ? {
        type: identityMatch.matchType,
        confidence: identityMatch.confidence
      } : null
    });
  } catch (err) {
    console.error('Error tracking event:', err);
    res.status(500).json({ error: 'Failed to track event' });
  }
});

// Identify user
app.post('/eventTracking/identify', async (req, res) => {
  const { sessionId, userData, requestId, visitorId, tenantId } = req.body;
  
  if (!tenantId) {
    return res.status(400).json({ error: 'tenantId is required' });
  }
  
  try {
    // Get database client
    const client = await getClient();
    
    // Get visitor details
    const sessionResult = await client.query(
      `SELECT visitor_id, ip_address, browser_details, 
              confidence_score, identification_method 
       FROM ${tenantId}.session_mappings 
       WHERE session_id = $1`,
      [sessionId]
    );

    if (sessionResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid session' });
    }

    const session = sessionResult.rows[0];

    // Verify visitor ID if provided
    if (requestId && visitorId) {
      const isValid = await verifyVisitorId(requestId, visitorId);
      if (!isValid) {
        return res.status(403).json({ error: 'Invalid visitor ID' });
      }
    }
    
    // Start transaction
    try {
      await client.query('BEGIN');
      
      // Update identity mapping for this visitor
      await client.query(
        `UPDATE ${tenantId}.identity_mappings 
         SET identity = $1,
             last_seen_at = CURRENT_TIMESTAMP
         WHERE visitor_id = $2`,
        [userData, session.visitor_id]
      );

      // Get all related identities (by IP and browser fingerprint)
      const relatedIdentities = await client.query(
        `SELECT DISTINCT visitor_id 
         FROM ${tenantId}.identity_mappings 
         WHERE ip_address = $1 
         AND visitor_id != $2
         AND browser_details->>'browserName' = $3
         AND browser_details->>'os' = $4`,
        [
          session.ip_address,
          session.visitor_id,
          session.browser_details.browserName,
          session.browser_details.os
        ]
      );

      // Update related identities
      if (relatedIdentities.rows.length > 0) {
        const relatedVisitorIds = relatedIdentities.rows.map(row => row.visitor_id);
        await client.query(
          `UPDATE ${tenantId}.identity_mappings 
           SET identity = $1,
               last_seen_at = CURRENT_TIMESTAMP
           WHERE visitor_id = ANY($2)`,
          [userData, relatedVisitorIds]
        );

        // Update events for all related identities
        await client.query(
          `UPDATE ${tenantId}.events 
           SET identity = $1 
           WHERE visitor_id = ANY($2)`,
          [userData, [...relatedVisitorIds, session.visitor_id]]
        );
      } else {
        // Update events just for this visitor
        await client.query(
          `UPDATE ${tenantId}.events 
           SET identity = $1 
           WHERE visitor_id = $2`,
          [userData, session.visitor_id]
        );
      }

      // Get the latest geolocation data
      const geoResult = await client.query(
        `SELECT geolocation, asn FROM ${tenantId}.identity_mappings 
         WHERE visitor_id = $1 
         ORDER BY last_seen_at DESC 
         LIMIT 1`,
        [session.visitor_id]
      );

      const geoData = geoResult.rows[0] || {};

      // Track identify event with geolocation
      await client.query(
        `INSERT INTO ${tenantId}.events 
         (session_id, visitor_id, event_name, properties, identity, 
          ip_address, browser_details, confidence_score, identification_method,
          geolocation) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          sessionId,
          session.visitor_id,
          'identify',
          userData,
          userData,
          session.ip_address,
          session.browser_details,
          session.confidence_score,
          session.identification_method,
          geoData.geolocation
        ]
      );
      
      await client.query('COMMIT');
      res.json({ 
        success: true, 
        identity: userData,
        relatedIdentitiesUpdated: relatedIdentities.rows.length
      });
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
app.get('/eventTracking/events/:sessionId', async (req, res) => {
  const { sessionId } = req.params;
  const { tenantId } = req.query;
  
  if (!tenantId) {
    return res.status(400).json({ error: 'tenantId is required' });
  }
  
  try {
    const client = await getClient();
    const result = await client.query(
      `SELECT * FROM ${tenantId}.events WHERE session_id = $1 ORDER BY timestamp DESC`,
      [sessionId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching events:', err);
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});

const PORT = process.env.PORT || 3008;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
