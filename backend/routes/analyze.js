const express = require('express');
const router = express.Router();
const safeBrowsing = require('../services/safeBrowsing');
const virusTotal = require('../services/virusTotal');
const urlFeatures = require('../services/urlFeatures');
const scoreCalculator = require('../utils/scoreCalculator');
const geminiExplain = require('../services/geminiExplain');

// Versioning for the analysis engine to clear cache on overhaul
const ENGINE_VERSION = "2.1"; 
const cache = new Map();

router.post('/', async (req, res) => {
    let { url } = req.body;
    if (!url) return res.status(400).json({ error: "URL is required" });

    // Handle missing protocol
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
    }

    try {
        new URL(url);
    } catch (e) {
        return res.status(400).json({ error: "Invalid URL format" });
    }

    // Cache check with VERSION control (Clears old inaccurate results)
    const cacheKey = `${ENGINE_VERSION}:${url}`;
    if (cache.has(cacheKey)) {
        const { timestamp, data } = cache.get(cacheKey);
        // Reduced cache to 5 minutes to ensure "Real-World" freshness during testing
        if (Date.now() - timestamp < 5 * 60 * 1000) {
            console.log(`Cache hit for ${url} (v${ENGINE_VERSION})`);
            return res.status(200).json(data);
        }
    }

    console.log(`Analyzing: ${url} (V${ENGINE_VERSION})`);

    try {
        const [safeBrowsingRes, virusTotalRes] = await Promise.all([
            safeBrowsing.check(url),
            virusTotal.scan(url)
        ]);

        const urlFeaturesRes = urlFeatures.extract(url);

        // Stage 1: Initial Score (Heuristic Only)
        const baseScoreRes = scoreCalculator.calculate(
            safeBrowsingRes, virusTotalRes, urlFeaturesRes
        );

        // Stage 2: Gemini Prediction and Verdict
        const geminiRes = await geminiExplain.generate({
            url, 
            score: baseScoreRes.score,
            level: baseScoreRes.level,
            safeBrowsing: safeBrowsingRes,
            virusTotalMaliciousEngines: virusTotalRes.maliciousCount,
            urlFeatures: urlFeaturesRes
        });

        // Stage 3: FINAL Score Adjustment based on AI Verdict
        const finalScoreRes = scoreCalculator.calculate(
            safeBrowsingRes, virusTotalRes, urlFeaturesRes, geminiRes.verdict
        );

        const finalResponse = {
            url,
            score: finalScoreRes.score,
            level: finalScoreRes.level,
            status: finalScoreRes.score >= 80 ? "Safe" : (finalScoreRes.score >= 40 ? "Suspicious" : "Unsafe"),
            phishingProbability: finalScoreRes.phishingProbability,
            threats: safeBrowsingRes.threats.concat(virusTotalRes.categories),
            virusTotal: virusTotalRes,
            urlFeatures: urlFeaturesRes,
            safeBrowsing: safeBrowsingRes,
            legalEstimation: geminiRes.legalEstimation,
            explanation: geminiRes.explanation,
            aiVerdict: geminiRes.verdict,
            scannedAt: new Date().toISOString(),
            engineVersion: ENGINE_VERSION
        };

        cache.set(cacheKey, { timestamp: Date.now(), data: finalResponse });
        res.status(200).json(finalResponse);
    } catch (err) {
        console.error('Analysis error:', err);
        res.status(500).json({ error: `Analysis failed: ${err.message}` });
    }
});

module.exports = router;
