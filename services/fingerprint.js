import { FingerprintJsServerApiClient, Region } from '@fingerprintjs/fingerprintjs-pro-server-api';

const fpClient = new FingerprintJsServerApiClient({
    apiKey: process.env.FPJS_PRIVATE_API_KEY,
    region: Region.Global
});

export async function getVisitorData(requestId) {
    console.count('times')
    try {
        console.log('Fetching visitor data for requestId:', requestId);
        
        // Get the event data
        const event = await fpClient.getEvent(requestId);
        console.log('Event data:', event);
        
        // Extract identification data from the nested structure
        const identificationData = event.products?.identification?.data;
        console.log(JSON.stringify(identificationData));
        if (!identificationData) {
            throw new Error('No identification data found in the response');
        }

        // Extract IP info data
        const ipInfoData = event.products?.ipInfo?.data?.v4;
        console.log({ipInfoData})
        console.log("Location Spoofing => ", JSON.stringify(event.products?.locationSpoofing));
        
        return {
            visitorId: identificationData.visitorId,
            ip: identificationData.ip,
            browserDetails: identificationData.browserDetails,
            incognito: identificationData.incognito,
            firstSeenAt: identificationData.firstSeenAt,
            lastSeenAt: identificationData.lastSeenAt,
            confidence: identificationData.confidence,
            // Additional data from ipInfo if available
            geolocation: ipInfoData?.geolocation,
            asn: ipInfoData?.asn,
            requestId,
            // Include raw data for debugging
            raw: {
                identification: identificationData,
                ipInfo: ipInfoData
            }
        }
    } catch (error) {
        console.error('Error getting visitor data:', error);
        throw error;
    }
}

// Helper function to verify visitor ID
export async function verifyVisitorId(requestId, claimedVisitorId) {
    try {
        const visitorData = await getVisitorData(requestId);
        return visitorData.visitorId === claimedVisitorId;
    } catch (error) {
        console.error('Error verifying visitor ID:', error);
        return false;
    }
}

export default {
    getVisitorData,
    verifyVisitorId
};
