function calculate(safeBrowsing, virusTotal, urlFeatures, aiVerdict = "SAFE") {
    let score = 100;

    // 1. Whitelist (for official domains)
    if (urlFeatures.isWhitelisted && !safeBrowsing.isMalicious && virusTotal.maliciousCount < 2) {
        return { score: 100, level: "SAFE", phishingProbability: 0 };
    }

    // 2. Direct Database Hits (Google/Virustotal)
    if (safeBrowsing.isMalicious) {
        score -= 50;
    }

    if (virusTotal.maliciousCount > 0 && virusTotal.totalEngines > 0) {
        const vtDeduction = (virusTotal.maliciousCount / virusTotal.totalEngines) * 60;
        score -= vtDeduction;
    }

    // 3. Heuristic / Pattern Analysis (for new/unseen sites)
    if (urlFeatures.hasHTTPS === false) score -= 15;
    if (urlFeatures.urlLength > 100) score -= 5;
    if (urlFeatures.hasIPAddress) score -= 30;
    if (urlFeatures.subdomainCount > 3) score -= 10;
    if (urlFeatures.hasMismatchedDomain) score -= 40;
    if (urlFeatures.tldRisk === "high") score -= 20;

    // Deep keyword penalty (for proxies/piracy)
    const pirateKeywords = ["proxy", "pirate", "torrent", "mirror", "unlocked", "crack", "mod"];
    const foundPirate = pirateKeywords.filter(k => urlFeatures.suspiciousKeywordsFound.includes(k));
    if (foundPirate.length > 0) {
        score -= 25; // Pirate/Proxy deduction
    } else if (urlFeatures.hasSuspiciousKeywords) {
        score -= 10;
    }

    // 4. AI-VERDICT OVERRIDE (Real World intelligence)
    // If Gemini says DANGER, we force the score down even if DBs are silent
    if (aiVerdict === "DANGER") {
        score = Math.min(score, 35); // Force into DANGEROUS/CRITICAL
    } else if (aiVerdict === "CAUTION") {
        score = Math.min(score, 65); // Force into SUSPICIOUS/LOW RISK
    }

    // Clamp score
    score = Math.max(0, Math.min(100, Math.round(score)));

    // Level mapping
    let level = "SAFE";
    if (score < 20) level = "CRITICAL";
    else if (score < 40) level = "DANGEROUS";
    else if (score < 60) level = "SUSPICIOUS";
    else if (score < 80) level = "LOW RISK";

    const phishingProbability = 100 - score;

    return { score, level, phishingProbability };
}

module.exports = { calculate };
