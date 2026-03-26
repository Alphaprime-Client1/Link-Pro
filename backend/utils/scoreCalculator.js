function calculate(safeBrowsing, virusTotal, urlFeatures, aiVerdict = "SAFE") {
    let score = 100;

    // 1. Whitelist Protection
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

    // 3. Independent Heuristic Analysis (The Key for New Illegal Sites)
    if (urlFeatures.hasHTTPS === false) score -= 20; // Increased penalty
    if (urlFeatures.urlLength > 120) score -= 10;
    if (urlFeatures.hasIPAddress) score -= 40;
    if (urlFeatures.subdomainCount > 3) score -= 15;
    if (urlFeatures.hasMismatchedDomain) score -= 45; // Brand impersonation is critical
    if (urlFeatures.tldRisk === "high") score -= 25;

    // Domain name keyword check (e.g. "pirate" or "proxy" in host)
    const criticalKeywords = ["proxy", "pirate", "torrent", "mirror", "crack", "unlocked", "leech", "magnet"];
    const foundCritical = criticalKeywords.filter(k => urlFeatures.domainKeywordsFound.includes(k));
    
    if (foundCritical.length > 0) {
        score -= 40; // Massive deduction for pirate keywords in domain
    } else if (urlFeatures.hasSuspiciousKeywords) {
        score -= 15;
    }

    // 4. AI-VERDICT OVERRIDE (Real World Intelligence)
    if (aiVerdict === "DANGER") {
        score = Math.min(score, 30); // Force into DANGEROUS/CRITICAL level
    } else if (aiVerdict === "CAUTION") {
        score = Math.min(score, 60); // Force into SUSPICIOUS/LOW RISK
    }

    // Clamp score
    score = Math.max(0, Math.min(100, Math.round(score)));

    // Final Mapping
    let level = "SAFE";
    if (score < 20) level = "CRITICAL";
    else if (score < 40) level = "DANGEROUS";
    else if (score < 60) level = "SUSPICIOUS";
    else if (score < 80) level = "LOW RISK";

    const phishingProbability = 100 - score;

    return { score, level, phishingProbability };
}

module.exports = { calculate };
