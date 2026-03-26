function calculate(safeBrowsing, virusTotal, urlFeatures) {
    let score = 100;

    // Deductions
    if (safeBrowsing.isMalicious) {
        score -= 40;
    }

    if (virusTotal.maliciousCount > 0) {
        const vtDeduction = (virusTotal.maliciousCount / virusTotal.totalEngines) * 30;
        score -= vtDeduction;
    }

    if (urlFeatures.hasHTTPS === false) {
        score -= 10;
    }

    if (urlFeatures.hasSuspiciousKeywords) {
        score -= 5;
    }

    if (urlFeatures.hasIPAddress) {
        score -= 10;
    }

    if (urlFeatures.subdomainCount > 3) {
        score -= 5;
    }

    if (urlFeatures.hasMismatchedDomain) {
        score -= 15;
    }

    if (urlFeatures.urlLength > 100) {
        score -= 5;
    }

    if (urlFeatures.tldRisk === "high") {
        score -= 10;
    } else if (urlFeatures.tldRisk === "medium") {
        score -= 3;
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
