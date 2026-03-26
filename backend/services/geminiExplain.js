const axios = require('axios');

async function generate(allData) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey || apiKey === 'your_key_here') {
        console.warn('Gemini API key not set.');
        return fallbackExplanation(allData.score);
    }

    try {
        const prompt = `You are an elite cybersecurity analyst. 
Analyze this specific URL scan data. Focus on BRAND IMPERSONATION and PHISHING PATTERNS.

Current Scanned URL: ${allData.url}
Score: ${allData.score}/100
Level: ${allData.level}

Indicators:
- Google Safe Browsing: ${JSON.stringify(allData.safeBrowsing)}
- VirusTotal Flags: ${allData.virusTotalMaliciousEngines}
- URL Features: ${JSON.stringify(allData.urlFeatures)}

Task:
1. Provide a professional 3–4 sentence report. 
   - If score is < 60, be very alarmist. 
   - If brand mismatch is detected (e.g. contains 'paypal' but not on paypal.com), classify it as PHISHING even if the score is somewhat high.
2. Legal Estimation: "Likely Legal", "Likely Illegal", or "Cannot Determine".

Language: Speak plainly but authoritatively. Mention specific triggers like keywords found or missing HTTPS.
Do NOT use markdown. Plain text only. No bolding.`;

        const response = await axios.post(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
            {
                contents: [{
                    parts: [{ text: prompt }]
                }]
            }
        );

        if (!response.data.candidates || response.data.candidates.length === 0) {
            return fallbackExplanation(allData.score);
        }

        const explanationText = response.data.candidates[0].content.parts[0].text;
        
        let legalEstimation = "Cannot Determine";
        const lowText = explanationText.toLowerCase();
        if (lowText.includes("illegal") || lowText.includes("phishing") || lowText.includes("scam")) {
            legalEstimation = "Likely Illegal";
        } else if (lowText.includes("legal") || lowText.includes("official")) {
            legalEstimation = "Likely Legal";
        }

        return { explanation: explanationText, legalEstimation: legalEstimation };
    } catch (error) {
        console.error('Gemini API error:', error.message);
        return fallbackExplanation(allData.score);
    }
}

function fallbackExplanation(score) {
    if (score >= 80) {
        return {
            explanation: "This URL appears safe based on preliminary scanning. No major threats were detected in the primary threat intelligence databases.",
            legalEstimation: "Likely Legal"
        };
    } else if (score >= 60) {
        return {
            explanation: "Low risk detected. While not overtly malicious, maintain caution if you are not familiar with the site.",
            legalEstimation: "Cannot Determine"
        };
    } else {
        return {
            explanation: "DANGER. This URL has strong indicators of being a phishing or malware threat. Avoid visiting this page to protect your browsing data.",
            legalEstimation: "Likely Illegal"
        };
    }
}

module.exports = { generate };
