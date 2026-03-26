const axios = require('axios');

async function generate(allData) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey || apiKey === 'your_key_here') {
        return { ...fallbackExplanation(allData.score), verdict: "UNKNOWN" };
    }

    try {
        const prompt = `You are a cybersecurity expert specializing in Malware and Phishing detection. Analyze this URL for real-world reliability: ${allData.url}.

        Data context for scan:
        - Current Score: ${allData.score}/100 
        - Levels: ${allData.level}
        - Google SafeBrowsing: ${JSON.stringify(allData.safeBrowsing)}
        - VirusTotal Flagged Engines: ${allData.virusTotalMaliciousEngines}
        - URL Features (Heuristics): ${JSON.stringify(allData.urlFeatures)}

        Mandatory Task:
        1. Write 3-4 professional sentences. 
           - Detect and flag "PIRATE PROXY" sites (e.g., piratebay, mirror sites, proxy sites for illegal content).
           - Detect and flag "BRAND IMPERSONATION" (e.g., paypal-secure-login.com).
        2. Assign a machine-readable verdict at the end. USE ONE OF THESE: [VERDICT:DANGER], [VERDICT:CAUTION], [VERDICT:SAFE].
           - Use [VERDICT:DANGER] if it's a proxy for illegal content or obvious phishing.

        Be blunt. Speak firmly. Do NOT use markdown. Plain text only. No bold.`;

        const response = await axios.post(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
            {
                contents: [{
                    parts: [{ text: prompt }]
                }]
            }
        );

        const explanationText = response.data.candidates[0].content.parts[0].text;
        
        // Accurate Verdict Extraction
        let verdict = "SAFE";
        if (explanationText.includes("VERDICT:DANGER")) verdict = "DANGER";
        else if (explanationText.includes("VERDICT:CAUTION")) verdict = "CAUTION";
        
        // Clean-up text for the user
        const finalExplanation = explanationText.replace(/\[VERDICT:.*\]/g, "").trim();

        let legalEstimation = "Cannot Determine";
        if (verdict === "DANGER") legalEstimation = "Likely Illegal";
        else if (verdict === "SAFE") legalEstimation = "Likely Legal";

        return { explanation: finalExplanation, legalEstimation, verdict };
    } catch (error) {
        console.error('Gemini error:', error.message);
        return { ...fallbackExplanation(allData.score), verdict: "UNKNOWN" };
    }
}

function fallbackExplanation(score) {
    if (score >= 80) {
        return {
            explanation: "Scan indicates low risk patterns. No major database matches.",
            legalEstimation: "Likely Legal"
        };
    } else {
        return {
            explanation: "CAUTION: Suspicious patterns detected (e.g., TLD risk, domain-string keywords, or brand mismatch).",
            legalEstimation: "Likely Illegal"
        };
    }
}

module.exports = { generate };
