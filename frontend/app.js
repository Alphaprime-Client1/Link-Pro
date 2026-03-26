document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('url-input');
    const scanBtn = document.getElementById('scan-btn');
    const loadingState = document.getElementById('loading-state');
    const loadingText = document.getElementById('loading-text');
    const resultCard = document.getElementById('result-card');
    const historyList = document.getElementById('history-list');

    // Load history
    renderHistory();

    scanBtn.addEventListener('click', async () => {
        const url = urlInput.value.trim();
        if (!url) return alert('Please enter a URL');

        await scanURL(url);
    });

    // Enter key support
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            scanBtn.click();
        }
    });

    async function scanURL(url) {
        // Reset/Hide UI
        resultCard.classList.add('hidden');
        loadingState.classList.remove('hidden');
        
        // Dynamic loading text cycling
        const phrases = [
            "Querying threat databases...",
            "Analyzing URL patterns...",
            "Running AI analysis...",
            "Generating report..."
        ];
        let i = 0;
        const interval = setInterval(() => {
            loadingText.innerText = phrases[i];
            i = (i + 1) % phrases.length;
        }, 1500);

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Analysis failed');
            }

            const data = await response.json();
            displayResults(data);
            saveToHistory(data);
        } catch (err) {
            alert(`Error: ${err.message}`);
        } finally {
            clearInterval(interval);
            loadingState.classList.add('hidden');
        }
    }

    function displayResults(data) {
        resultCard.classList.remove('hidden');
        
        // Header
        const levelBadge = document.getElementById('level-badge');
        const scoreText = document.getElementById('score-text');
        const scoreBar = document.getElementById('score-bar');
        
        levelBadge.innerText = data.level;
        levelBadge.className = 'badge'; // Reset classes
        const levelSlug = data.level.toLowerCase().replace(' ', '_');
        levelBadge.classList.add(`level-${levelSlug}`);
        
        scoreText.innerText = `Score: ${data.score}/100`;
        scoreBar.style.width = `${data.score}%`;
        
        // Update bar color based on score
        let barColor = '--safe-green';
        if (data.score < 20) barColor = '--critical-red';
        else if (data.score < 40) barColor = '--danger-red';
        else if (data.score < 60) barColor = '--warning-orange';
        else if (data.score < 80) barColor = '--low-risk-green';
        scoreBar.style.background = `var(${barColor})`;

        // Indicator functions
        updateIndicator('ind-safe-browsing', data.safeBrowsing.isMalicious ? '🔴 UNSAFE' : '🟢 SAFE', !data.safeBrowsing.isMalicious);
        updateIndicator('ind-virus-total', `${data.virusTotal.maliciousCount}/${data.virusTotal.totalEngines} engines flagged`, data.virusTotal.maliciousCount === 0);
        updateIndicator('ind-https', data.urlFeatures.hasHTTPS ? '🟢 Secure (HTTPS)' : '🔴 Not Secure', data.urlFeatures.hasHTTPS);
        updateIndicator('ind-keywords', data.urlFeatures.hasSuspiciousKeywords ? `🔴 ${data.urlFeatures.suspiciousKeywordsFound.join(', ')}` : '🟢 NONE', !data.urlFeatures.hasSuspiciousKeywords);
        updateIndicator('ind-mismatch', data.urlFeatures.hasMismatchedDomain ? '🔴 Detected' : '🟢 NONE', !data.urlFeatures.hasMismatchedDomain);
        updateIndicator('ind-tld', `${data.urlFeatures.tldRisk.toUpperCase()} RISK`, data.urlFeatures.tldRisk === 'low');

        // AI specific
        document.getElementById('legal-estimation').innerText = data.legalEstimation;
        document.getElementById('ai-explanation').innerText = data.explanation;

        // Scroll into view
        resultCard.scrollIntoView({ behavior: 'smooth' });
    }

    function updateIndicator(id, text, isSafe) {
        const el = document.getElementById(id);
        const iconEl = el.querySelector('.icon');
        const statusEl = el.querySelector('.status');
        
        iconEl.innerText = isSafe ? '🟢' : '🔴';
        statusEl.innerText = text;
        statusEl.style.color = isSafe ? 'var(--safe-green)' : 'var(--danger-red)';
    }

    function saveToHistory(data) {
        let history = JSON.parse(localStorage.getItem('scanHistory') || '[]');
        
        // Remove duplicate URLs
        history = history.filter(item => item.url !== data.url);
        
        // Add new one to top
        history.unshift({
            url: data.url,
            score: data.score,
            level: data.level,
            scannedAt: data.scannedAt
        });

        // Limit to 5
        history = history.slice(0, 5);
        localStorage.setItem('scanHistory', JSON.stringify(history));
        renderHistory();
    }

    function renderHistory() {
        const history = JSON.parse(localStorage.getItem('scanHistory') || '[]');
        historyList.innerHTML = '';
        
        history.forEach(item => {
            const el = document.createElement('div');
            el.className = 'history-item';
            el.innerHTML = `
                <div class="history-url">${item.url}</div>
                <div class="history-meta">${item.score}/100 [${item.level}]</div>
            `;
            el.addEventListener('click', () => {
                urlInput.value = item.url;
                scanURL(item.url);
            });
            historyList.appendChild(el);
        });
    }
});
