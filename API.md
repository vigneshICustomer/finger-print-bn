# Event Tracking SDK Documentation

## Overview

This SDK provides a simple way to track user events and manage user identity across sessions and devices. All tracking is handled server-side, ensuring privacy and reliability.

## Installation

Add the SDK to your HTML:

```html
<script src="/event-tracker.js"></script>
```

The SDK automatically initializes and creates a global `EventTracker` instance.

## API Reference

### Page Visit Tracking

```javascript
await EventTracker.page_visit([properties])
```

Tracks a page visit event with URL, title, and referrer information.

**Parameters:**
- `properties` (optional): Object - Additional properties to include with the page visit
  ```javascript
  {
    section?: string,    // Section of the website
    category?: string,   // Page category
    [key: string]: any  // Any additional custom properties
  }
  ```

**Returns:** Promise<Object> - The tracked event object

**Example:**
```javascript
// Basic page visit tracking
await EventTracker.page_visit();

// Page visit with custom properties
await EventTracker.page_visit({
    section: 'products',
    category: 'electronics',
    customProperty: 'value'
});
```

### Custom Event Tracking

```javascript
await EventTracker.track(eventName, [properties])
```

Tracks a custom event with specified properties.

**Parameters:**
- `eventName` (required): String - Name of the event to track
- `properties` (optional): Object - Properties associated with the event
  ```javascript
  {
    [key: string]: any  // Any custom properties
  }
  ```

**Returns:** Promise<Object> - The tracked event object

**Example:**
```javascript
// Track a button click
await EventTracker.track('button_click', {
    buttonId: 'submit-form',
    buttonText: 'Submit',
    pageSection: 'checkout'
});

// Track a form submission
await EventTracker.track('form_submit', {
    formId: 'contact-form',
    formData: {
        email: 'user@example.com',
        subject: 'Support'
    }
});
```

### User Identification

```javascript
await EventTracker.identify(userProperties)
```

Identifies a user and updates all their previous events with the provided identity information.

**Parameters:**
- `userProperties` (required): Object - User identification properties
  ```javascript
  {
    email?: string,     // User's email
    name?: string,      // User's name
    userId?: string,    // Unique user ID
    [key: string]: any  // Any additional user properties
  }
  ```

**Returns:** Promise<Object> - The identify event object

**Example:**
```javascript
// Identify a user
await EventTracker.identify({
    email: 'user@example.com',
    name: 'John Doe',
    userId: '12345',
    role: 'customer',
    plan: 'premium'
});
```

## Identity Stitching

The SDK automatically handles identity stitching through two mechanisms:

1. **Session Tracking**: Events from the same browsing session are automatically linked.
2. **IP Address Matching**: Events from the same IP address are linked when a user identifies themselves.

When `identify()` is called:
- All previous events from the same session are updated with the new identity
- All anonymous events from the same IP address are updated with the new identity
- Future events are automatically associated with this identity

This ensures a complete user journey across different sessions and devices.

## Event Object Structure

All tracked events follow this structure:

```javascript
{
    id: number,           // Unique event ID
    session_id: string,   // Session identifier
    visitor_id: string,   // Unique visitor ID
    event_name: string,   // Name of the event
    properties: {         // Event properties
        [key: string]: any
    },
    identity: {           // User identity (if identified)
        email?: string,
        name?: string,
        userId?: string,
        [key: string]: any
    },
    ip_address: string,   // Client IP address
    timestamp: string     // ISO timestamp
}
```

## Error Handling

All methods return promises and should be handled with try-catch:

```javascript
try {
    await EventTracker.track('important_action', {
        actionId: '12345'
    });
} catch (error) {
    console.error('Failed to track event:', error);
}
```

## Browser Compatibility

The SDK is compatible with all modern browsers:
- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)

For older browsers, ensure you have appropriate polyfills for:
- Promises
- Fetch API
- async/await
