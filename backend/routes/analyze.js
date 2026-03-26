const express = require('express');
const router = express.Router();
const safeBrowsing = require('../services/safeBrowsing');
const virusTotal = require('../services/virusTotal');
const urlFeatures = require('../services/urlFeatures');
const scoreCalculator = require('../utils/scoreCalculator');
const geminiExplain = require('../services/geminiExplain');

// Use a simple in-memory cache for demo/rate-limiting
const cache = new Map();

router.post('/', async (req, res) => {
    let { url } = req.body;
    if (!url) {
        return res.status(400).json({ error: "URL is required" });
    }

    // Ensure it has a protocol for the URL object to work
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'http://' + url;
    }

    // Basic URL validation
    try {
        new URL(url);
    } catch (e) {
        return res.status(400).json({ error: "Invalid URL format" });
    }

    // Cache check
    const cacheKey = url;
    if (cache.has(cacheKey)) {
        const { timestamp, data } = cache.get(cacheKey);
        // 30 minute cache as requested
        if (Date.now() - timestamp < 30 * 60 * 1000) {
            console.log(`Cache hit for ${url}`);
            return res.status(200).json(data);
        }
    }

    console.log(`Analyzing: ${url}`);

    try {
        // Run lookups in parallel where possible
        // But VirusTotal has a 3-second delay, so it will take at least that long
        const [safeBrowsingRes, virusTotalRes] = await Promise.all([
            safeBrowsing.check(url),
            virusTotal.scan(url)
        ]);

        const urlFeaturesRes = urlFeatures.extract(url);

        const scoreRes = scoreCalculator.calculate(
            safeBrowsingRes, 
            virusTotalRes, 
            urlFeaturesRes
        );

        const aiContext = {
            url, 
            score: scoreRes.score, 
            level: scoreRes.level,
            safeBrowsing: safeBrowsingRes,
            virusTotalMaliciousEngines: virusTotalRes.maliciousCount,
            urlFeatures: urlFeaturesRes
        };

        const geminiRes = await geminiExplain.generate(aiContext);

        const finalResponse = {
            url,
            score: scoreRes.score,
            level: scoreRes.level,
            status: scoreRes.score >= 80 ? "Safe" : (scoreRes.score >= 40 ? "Suspicious" : "Unsafe"),
            phishingProbability: scoreRes.phishingProbability,
            threats: safeBrowsingRes.threats.concat(virusTotalRes.categories),
            virusTotal: virusTotalRes,
            urlFeatures: urlFeaturesRes,
            safeBrowsing: safeBrowsingRes,
            legalEstimation: geminiRes.legalEstimation,
            explanation: geminiRes.explanation,
            scannedAt: new Date().toISOString()
        };

        // Update cache
        cache.set(cacheKey, { timestamp: Date.now(), data: finalResponse });
        
        res.status(200).json(finalResponse);
    } catch (err) {
        console.error('Analysis error:', err.message);
        res.status(500).json({ error: `Analysis failed: ${err.message}` });
    }
});

module.exports = router;
