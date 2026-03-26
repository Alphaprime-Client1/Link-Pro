const axios = require('axios');

async function check(url) {
    const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
    if (!apiKey || apiKey === 'your_key_here') {
        console.warn('Google Safe Browsing API key not set.');
        return { isMalicious: false, threats: [], error: "API key not configured" };
    }

    try {
        const response = await axios.post(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
            {
                client: { clientId: "url-analyzer", clientVersion: "1.0" },
                threatInfo: {
                    threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [{ url: url }]
                }
            }
        );

        if (response.data.matches && response.data.matches.length > 0) {
            const threatTypes = response.data.matches.map(match => match.threatType);
            return { isMalicious: true, threats: threatTypes };
        } else {
            return { isMalicious: false, threats: [] };
        }
    } catch (error) {
        console.error('Google Safe Browsing API error:', error.message);
        return { isMalicious: false, threats: [], error: "API unavailable" };
    }
}

module.exports = { check };
