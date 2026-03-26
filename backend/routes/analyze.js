const express = require('express');
const router = express.Router();
const safeBrowsing = require('../services/safeBrowsing');
const virusTotal = require('../services/virusTotal');
const urlFeatures = require('../services/urlFeatures');
const scoreCalculator = require('../utils/scoreCalculator');
const geminiExplain = require('../services/geminiExplain');

const cache = new Map();

router.post('/', async (req, res) => {
    let { url } = req.body;
    if (!url) return res.status(400).json({ error: "URL is required" });

    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
    }

    try {
        new URL(url);
    } catch (e) {
        return res.status(400).json({ error: "Invalid URL format" });
    }

    const cacheKey = url;
    if (cache.has(cacheKey)) {
        const { timestamp, data } = cache.get(cacheKey);
        if (Date.now() - timestamp < 30 * 60 * 1000) {
            return res.status(200).json(data);
        }
    }

    try {
        const [safeBrowsingRes, virusTotalRes] = await Promise.all([
            safeBrowsing.check(url),
            virusTotal.scan(url)
        ]);

        const urlFeaturesRes = urlFeatures.extract(url);

        // 1. Calculate Base Score
        const baseScoreRes = scoreCalculator.calculate(
            safeBrowsingRes, virusTotalRes, urlFeaturesRes
        );

        // 2. Call Gemini with context
        const geminiRes = await geminiExplain.generate({
            url, 
            score: baseScoreRes.score,
            safeBrowsing: safeBrowsingRes,
            virusTotalMaliciousEngines: virusTotalRes.maliciousCount,
            urlFeatures: urlFeaturesRes
        });

        // 3. RE-CALCULATE Final Score with AI Verdict
        const finalScoreRes = scoreCalculator.calculate(
            safeBrowsingRes, 
            virusTotalRes, 
            urlFeaturesRes, 
            geminiRes.verdict // AI Verdict (DANGER, CAUTION, SAFE)
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
            scannedAt: new Date().toISOString()
        };

        cache.set(cacheKey, { timestamp: Date.now(), data: finalResponse });
        res.status(200).json(finalResponse);
    } catch (err) {
        console.error('Analysis error:', err);
        res.status(500).json({ error: `Analysis failed: ${err.message}` });
    }
});

module.exports = router;
