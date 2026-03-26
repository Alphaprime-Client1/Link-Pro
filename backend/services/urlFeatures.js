const { URL } = require('url');

function extract(urlStr) {
    const hasHTTPS = urlStr.startsWith("https://");

    const suspiciousKeywords = [
        "login", "verify", "secure", "account", "update", "confirm",
        "banking", "paypal", "free", "win", "prize", "click", "password",
        "reset", "urgent", "limited", "suspend", "blocked", "claim", "offer"
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
    let isWhitelisted = false;

    // Top official domains to avoid false flags
    const whitelist = [
        "google.com", "youtube.com", "facebook.com", "microsoft.com", 
        "apple.com", "amazon.com", "netflix.com", "twitter.com", 
        "instagram.com", "linkedin.com", "github.com", "wikipedia.org",
        "paypal.com", "bankofamerica.com", "chase.com", "wellsfargo.com"
    ];

    try {
        const parsedURL = new URL(urlStr);
        const hostName = parsedURL.hostname.toLowerCase();

        // Check Whitelist
        isWhitelisted = whitelist.some(domain => hostName === domain || hostName.endsWith("." + domain));

        // IP address check
        const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        hasIPAddress = ipRegex.test(hostName);

        // Subdomain count
        subdomainCount = (hostName.split('.').length - 1);

        // Domain mismatch check (Heuristic: Brand name in path/subdomain but not core domain)
        const brandNames = ["paypal", "google", "facebook", "amazon", "apple", "microsoft", "netflix", "instagram", "chase"];
        for(let brand of brandNames) {
            const hostParts = hostName.split('.');
            const mainDomain = hostParts.length >= 2 ? hostParts[hostParts.length - 2] : hostName;
            
            // If brand name found anywhere in URL...
            if (urlStr.toLowerCase().includes(brand)) {
                // ...but the core domain is NOT that brand
                if (!mainDomain.includes(brand)) {
                    hasMismatchedDomain = true;
                    break;
                }
            }
        }

        // TLD Risk
        const highRiskTLDs = [".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".cf", ".ga", ".loan", ".zip", ".mov"];
        const tldMatch = hostName.match(/\.[a-z]+$/);
        if (tldMatch) {
            const tld = tldMatch[0];
            if (highRiskTLDs.includes(tld)) tldRisk = "high";
        }
    } catch (e) {
        console.error('URL extraction error', e.message);
    }

    return {
        hasHTTPS,
        hasSuspiciousKeywords,
        suspiciousKeywordsFound,
        urlLength,
        hasIPAddress,
        subdomainCount,
        hasMismatchedDomain,
        tldRisk,
        isWhitelisted
    };
}

module.exports = { extract };
