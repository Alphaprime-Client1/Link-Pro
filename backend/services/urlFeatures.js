const { URL } = require('url');

function extract(urlStr) {
    const hasHTTPS = urlStr.startsWith("https://");

    const suspiciousKeywords = [
        "login", "verify", "secure", "account", "update", "confirm",
        "banking", "paypal", "free", "win", "prize", "click", "password",
        "reset", "urgent", "limited", "suspend", "blocked"
    ];

    const suspiciousKeywordsFound = suspiciousKeywords.filter(keyword =>
        urlStr.toLowerCase().includes(keyword.toLowerCase())
    );

    const hasSuspiciousKeywords = suspiciousKeywordsFound.length > 0;

    const urlLength = urlStr.length;

    let hasIPAddress = false;
    let subdomainCount = 0;
    let hasMismatchedDomain = false;
    let tldRisk = "low";

    try {
        const parsedURL = new URL(urlStr);
        const hostName = parsedURL.hostname;

        // Correct IP address check (very basic)
        const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        hasIPAddress = ipRegex.test(hostName);

        // Subdomain count (count dots in hostname - 1)
        subdomainCount = (hostName.split('.').length - 1);

        // Domain mismatch check
        const brandNames = ["paypal", "google", "facebook", "amazon", "apple", "microsoft", "netflix"];
        for(let brand of brandNames) {
            // Check if brand is in the full URL but NOT in the domain
            const parts = hostName.split('.');
            const domain = parts.slice(-2).join('.');
            if (urlStr.toLowerCase().includes(brand) && !domain.includes(brand)) {
                hasMismatchedDomain = true;
                break;
            }
        }

        // TLD Risk
        const lowRiskTLDs = [".com", ".org", ".net", ".edu", ".gov"];
        const mediumRiskTLDs = [".info", ".biz", ".co"];
        const highRiskTLDs = [".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".cf", ".ga", ".loan"];

        const tldMatch = hostName.match(/\.[a-z]+$/);
        if (tldMatch) {
            const tld = tldMatch[0];
            if (highRiskTLDs.includes(tld)) tldRisk = "high";
            else if (mediumRiskTLDs.includes(tld)) tldRisk = "medium";
            else if (lowRiskTLDs.includes(tld)) tldRisk = "low";
        }
    } catch (e) {
        console.error('URL parsing failed', e.message);
    }

    return {
        hasHTTPS,
        hasSuspiciousKeywords,
        suspiciousKeywordsFound,
        urlLength,
        hasIPAddress,
        subdomainCount,
        hasMismatchedDomain,
        tldRisk
    };
}

module.exports = { extract };
