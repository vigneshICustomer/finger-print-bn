// Event Tracking SDK
class EventTracker {
    constructor(options = {}) {
        this.apiUrl = options.apiUrl || 'http://localhost:3000/api';
        this.sessionId = null;
        this.identity = null;
        this.initialize();
    }

    async initialize() {
        try {
            const response = await fetch(`${this.apiUrl}/init`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error('Failed to initialize tracking');
            }
            
            const data = await response.json();
            this.sessionId = data.sessionId;
            this.identity = data.identity;

            // If there's an existing identity, log it
            if (this.identity) {
                console.log('Session initialized with existing identity:', this.identity);
            }
        } catch (error) {
            console.error('Error initializing tracking:', error);
        }
    }

    async _ensureInitialized() {
        if (!this.sessionId) {
            await this.initialize();
        }
    }

    async _trackEvent(eventName, properties = {}) {
        await this._ensureInitialized();

        try {
            const response = await fetch(`${this.apiUrl}/track`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    sessionId: this.sessionId,
                    eventName,
                    properties
                })
            });

            if (!response.ok) {
                throw new Error('Failed to track event');
            }

            const result = await response.json();
            console.log('Event tracked:', result);
            return result;
        } catch (error) {
            console.error('Error tracking event:', error);
            throw error;
        }
    }

    async page_visit(pageProperties = {}) {
        return this._trackEvent('page_visit', {
            url: window.location.href,
            title: document.title,
            referrer: document.referrer,
            ...pageProperties
        });
    }

    async track(eventName, eventProperties = {}) {
        return this._trackEvent(eventName, eventProperties);
    }

    async identify(userProperties) {
        await this._ensureInitialized();

        try {
            const response = await fetch(`${this.apiUrl}/identify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    sessionId: this.sessionId,
                    userData: userProperties
                })
            });

            if (!response.ok) {
                throw new Error('Failed to identify user');
            }

            const result = await response.json();
            this.identity = result.identity;
            console.log('User identified:', result);
            return result;
        } catch (error) {
            console.error('Error identifying user:', error);
            throw error;
        }
    }

    async getAllEvents() {
        await this._ensureInitialized();
        
        try {
            const response = await fetch(`${this.apiUrl}/events/${this.sessionId}`);
            if (!response.ok) {
                throw new Error('Failed to fetch events');
            }
            return await response.json();
        } catch (error) {
            console.error('Error fetching events:', error);
            throw error;
        }
    }
}

// Create a global instance
document.addEventListener('DOMContentLoaded', () => {
    window.EventTracker = new EventTracker();
});
