import pool from '../db/connection.js';

// Cache for identity lookups (TTL: 5 minutes)
const identityCache = new Map();
const CACHE_TTL = 5 * 60 * 1000;

/**
 * Get identity with caching
 */
export async function getIdentityByVisitorId(visitorId) {
    const cacheKey = `visitor_${visitorId}`;
    const cached = identityCache.get(cacheKey);
    
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
        return cached.data;
    }

    const result = await pool.query(
        `SELECT identity, confidence_score, identification_method, browser_details,
                geolocation, asn, last_seen_at
         FROM identity_mappings 
         WHERE visitor_id = $1 
         ORDER BY last_seen_at DESC 
         LIMIT 1`,
        [visitorId]
    );

    if (result.rows[0]) {
        identityCache.set(cacheKey, {
            data: result.rows[0],
            timestamp: Date.now()
        });
    }

    return result.rows[0];
}

/**
 * Batch insert events for better performance
 */
export async function batchInsertEvents(events) {
    const values = events.map(event => [
        event.sessionId,
        event.visitorId,
        event.eventName,
        event.properties,
        event.identity,
        event.ipAddress,
        event.browserDetails,
        event.confidenceScore,
        event.identificationMethod,
        event.geolocation
    ]).flat();

    const placeholders = events.map((_, i) => {
        const base = i * 10; // 10 columns
        return `($${base + 1}, $${base + 2}, $${base + 3}, $${base + 4}, $${base + 5}, $${base + 6}, $${base + 7}, $${base + 8}, $${base + 9}, $${base + 10})`;
    }).join(', ');

    return pool.query(
        `INSERT INTO events 
         (session_id, visitor_id, event_name, properties, identity, 
          ip_address, browser_details, confidence_score, 
          identification_method, geolocation)
         VALUES ${placeholders}
         RETURNING *`,
        values
    );
}

/**
 * Optimized identity stitching query
 */
export async function findRelatedIdentities(visitorId, ip, browserDetails) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // First try exact fingerprint match
        const fingerprintMatch = await client.query(
            `SELECT * FROM identity_mappings 
             WHERE visitor_id = $1
             FOR UPDATE`,
            [visitorId]
        );

        if (fingerprintMatch.rows[0]) {
            await client.query('COMMIT');
            return {
                type: 'fingerprint',
                confidence: 1.0,
                data: fingerprintMatch.rows[0]
            };
        }

        // Then try IP + browser match
        if (browserDetails) {
            const ipBrowserMatch = await client.query(
                `SELECT * FROM identity_mappings 
                 WHERE ip_address = $1 
                 AND browser_details->>'browserName' = $2
                 AND browser_details->>'os' = $3
                 ORDER BY last_seen_at DESC
                 LIMIT 1
                 FOR UPDATE`,
                [ip, browserDetails.browserName, browserDetails.os]
            );

            if (ipBrowserMatch.rows[0]) {
                await client.query('COMMIT');
                return {
                    type: 'ip_browser',
                    confidence: 0.8,
                    data: ipBrowserMatch.rows[0]
                };
            }
        }

        // Finally try IP-only match
        const ipMatch = await client.query(
            `SELECT * FROM identity_mappings 
             WHERE ip_address = $1
             ORDER BY last_seen_at DESC
             LIMIT 1
             FOR UPDATE`,
            [ip]
        );

        await client.query('COMMIT');
        return ipMatch.rows[0] ? {
            type: 'ip',
            confidence: 0.5,
            data: ipMatch.rows[0]
        } : null;

    } catch (error) {
        await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
    }
}

/**
 * Efficient session validation
 */
export async function validateSession(sessionId) {
    const result = await pool.query(
        `SELECT visitor_id, ip_address, browser_details, 
                confidence_score, identification_method
         FROM session_mappings 
         WHERE session_id = $1
         AND created_at > NOW() - INTERVAL '24 hours'`,
        [sessionId]
    );
    return result.rows[0];
}

/**
 * Update identity with transaction
 */
export async function updateIdentity(visitorId, identity, relatedIds = []) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Update main identity
        await client.query(
            `UPDATE identity_mappings 
             SET identity = $1,
                 last_seen_at = CURRENT_TIMESTAMP
             WHERE visitor_id = $2`,
            [identity, visitorId]
        );

        // Update related identities if any
        if (relatedIds.length > 0) {
            await client.query(
                `UPDATE identity_mappings 
                 SET identity = $1,
                     last_seen_at = CURRENT_TIMESTAMP
                 WHERE visitor_id = ANY($2)`,
                [identity, relatedIds]
            );

            // Update events for all identities
            await client.query(
                `UPDATE events 
                 SET identity = $1 
                 WHERE visitor_id = ANY($2)`,
                [identity, [...relatedIds, visitorId]]
            );
        }

        await client.query('COMMIT');
    } catch (error) {
        await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
    }
}

// Clear expired cache entries periodically
setInterval(() => {
    const now = Date.now();
    for (const [key, value] of identityCache.entries()) {
        if (now - value.timestamp > CACHE_TTL) {
            identityCache.delete(key);
        }
    }
}, CACHE_TTL);
