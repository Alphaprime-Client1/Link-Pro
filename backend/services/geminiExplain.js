const axios = require('axios');

async function generate(allData) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey || apiKey === 'your_key_here') {
        return fallbackExplanation(allData.score);
    }

    try {
        const prompt = `You are an elite cybersecurity agent. Analyze this URL for real-world risk: ${allData.url}.

        Data:
        - Score so far: ${allData.score}/100
        - SafeBrowsing: ${JSON.stringify(allData.safeBrowsing)}
        - VirusTotal Flags: ${allData.virusTotalMaliciousEngines}
        - Features (Heuristics): ${JSON.stringify(allData.urlFeatures)}

        Task:
        1. Write a 3–4 sentence report. Focus on why it looks safe OR why it's a proxy, pirate, or phishing site.
        2. Give a machine-readable verdict at the end. Choose ONE: [VERDICT:SAFE], [VERDICT:CAUTION], [VERDICT:DANGER].
        
        Example: "This site is a proxy for copyright material. VERDICT:DANGER"
        
        Be authoritative. Do NOT mention being an AI. No markdown.`;

        const response = await axios.post(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
            {
                contents: [{
                    parts: [{ text: prompt }]
                }]
            }
        );

        const explanationText = response.data.candidates[0].content.parts[0].text;
        
        // Extract verdict
        let verdict = "SAFE";
        if (explanationText.includes("VERDICT:DANGER")) verdict = "DANGER";
        else if (explanationText.includes("VERDICT:CAUTION")) verdict = "CAUTION";
        
        // Clean text (remove verdict tag for UI)
        const uiText = explanationText.replace(/\[VERDICT:.*\]/g, "");

        let legalEstimation = "Cannot Determine";
        if (verdict === "DANGER") legalEstimation = "Likely Illegal";
        else if (verdict === "SAFE") legalEstimation = "Likely Legal";

        return { explanation: uiText, legalEstimation, verdict };
    } catch (error) {
        return { ...fallbackExplanation(allData.score), verdict: "UNKNOWN" };
    }
}

function fallbackExplanation(score) {
    if (score >= 80) {
        return {
            explanation: "URL appears safe based on preliminary pattern matching.",
            legalEstimation: "Likely Legal"
        };
    } else {
        return {
            explanation: "CAUTION: This URL has suspicious characteristics (length, host patterns, or TLD risk).",
            legalEstimation: "Likely Illegal"
        };
    }
}

module.exports = { generate };
