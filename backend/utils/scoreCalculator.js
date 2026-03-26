function calculate(safeBrowsing, virusTotal, urlFeatures) {
    let score = 100;

    // 1. Whitelist Protection
    // If it's a known top-tier domain and SafeBrowsing says it's SAFE, 
    // ignore small VirusTotal flags (often false positives)
    if (urlFeatures.isWhitelisted && !safeBrowsing.isMalicious) {
        if (virusTotal.maliciousCount < 3) {
            return { score: 100, level: "SAFE", phishingProbability: 0 };
        }
    }

    // 2. Direct Threat Deductions
    if (safeBrowsing.isMalicious) {
        score -= 50; // Increased penalty
    }

    if (virusTotal.maliciousCount > 0 && virusTotal.totalEngines > 0) {
        // More aggressive VT penalty
        const vtDeduction = (virusTotal.maliciousCount / virusTotal.totalEngines) * 60;
        score -= vtDeduction;
    }

    // 3. Heuristic Deductions (THE KEY FOR NEW ILLEGAL SITES)
    if (urlFeatures.hasHTTPS === false) {
        score -= 15;
    }

    if (urlFeatures.hasSuspiciousKeywords) {
        score -= 10;
    }

    if (urlFeatures.hasIPAddress) {
        score -= 25; // Massive penalty for IP-based URLs
    }

    if (urlFeatures.subdomainCount > 3) {
        score -= 10;
    }

    if (urlFeatures.hasMismatchedDomain) {
        score -= 30; // Massive penalty for brand impersonation
    }

    if (urlFeatures.urlLength > 100) {
        score -= 5;
    }

    if (urlFeatures.tldRisk === "high") {
        score -= 15;
    }

    // 4. Force Minimum for obvious phish
    // If domain mismatch + suspicious keywords are found, it's almost certainly a phish
    if (urlFeatures.hasMismatchedDomain && urlFeatures.hasSuspiciousKeywords) {
        score = Math.min(score, 30);
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
