const axios = require('axios');

async function generate(allData) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey || apiKey === 'your_key_here') {
        console.warn('Gemini API key not set.');
        return fallbackExplanation(allData.score);
    }

    try {
        const prompt = `You are a cybersecurity expert. Analyze the given URL scan data and provide:
1. A clear 3–4 sentence explanation of WHY this URL is safe or unsafe
2. Legal estimation: "Likely Legal", "Likely Illegal", or "Cannot Determine"

Be specific. Mention which indicators triggered. Speak to a non-technical user.
Do NOT use markdown. Plain text only.

Input: ${JSON.stringify(allData)}`;

        const response = await axios.post(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`,
            {
                contents: [{
                    parts: [{ text: prompt }]
                }]
            }
        );

        const explanationText = response.data.candidates[0].content.parts[0].text;
        
        // Parse legal estimation
        let legalEstimation = "Cannot Determine";
        if (explanationText.toLowerCase().includes("illegal")) {
            legalEstimation = "Likely Illegal";
        } else if (explanationText.toLowerCase().includes("legal")) {
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
    } else if (score >= 40) {
        return {
            explanation: "This URL is considered suspicious. Some indicators, like URL format or obscure TLDs, suggest caution is necessary.",
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
