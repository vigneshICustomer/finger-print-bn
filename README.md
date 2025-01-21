# Event Tracking System

A robust event tracking system that captures user events and manages user identity based on client IP and browser fingerprinting.

## Features

- User event tracking (page visits, custom events)
- User identification and identity stitching
- IP-based anonymous user tracking
- Browser fingerprinting using FingerprintJS
- PostgreSQL storage for events
- Real-time event updates

## Setup

1. Install dependencies:
```bash
npm install
```

2. Configure environment variables in `.env`:
```env
DB_USER=your_db_user
DB_HOST=your_db_host
DB_NAME=your_db_name
DB_PASSWORD=your_db_password
DB_PORT=5432
PORT=3000
```

3. Start the server:
```bash
npm run dev
```

## Usage

Add the SDK to your HTML:

```html
<script src="https://cdn.jsdelivr.net/npm/@fingerprintjs/fingerprintjs@3/dist/fp.umd.min.js"></script>
<script src="/event-tracker.js"></script>
```

Track events:

```javascript
// Track page visits
await EventTracker.page_visit();

// Track custom events
await EventTracker.track('button_click', {
    buttonName: 'submit',
    category: 'form'
});

// Identify users
await EventTracker.identify({
    email: 'user@example.com',
    name: 'John Doe',
    userId: '12345'
});
```

## API Endpoints

- `POST /api/track` - Track an event
- `POST /api/identify` - Identify a user
- `GET /api/events/:visitorId` - Get all events for a visitor

## Database Schema

The events table structure:

```sql
CREATE TABLE events (
    id SERIAL PRIMARY KEY,
    visitor_id VARCHAR(255) NOT NULL,
    event_name VARCHAR(255) NOT NULL,
    properties JSONB,
    identity JSONB,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
