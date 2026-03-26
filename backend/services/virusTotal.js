const axios = require('axios');
const formData = require('form-data');

async function scan(url) {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey || apiKey === 'your_key_here') {
        console.warn('VirusTotal API key not set.');
        return { maliciousCount: 0, totalEngines: 0, categories: [], error: "API key not configured" };
    }

    try {
        const form = new formData();
        form.append('url', url);

        const response = await axios.post('https://www.virustotal.com/api/v3/urls', form, {
            headers: {
                ...form.getHeaders(),
                'x-apikey': apiKey
            }
        });

        const analysisId = response.data.data.id;
        console.log(`VirusTotal analysis ID: ${analysisId}`);

        // Wait for analysis to complete (3 seconds as requested)
        await new Promise(resolve => setTimeout(resolve, 3000));

        const analysisResponse = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            headers: { 'x-apikey': apiKey }
        });

        const stats = analysisResponse.data.data.attributes.stats;
        const meta = analysisResponse.data.meta;
        
        const maliciousCount = stats.malicious;
        const totalEngines = stats.malicious + stats.harmless + stats.suspicious + stats.undetected;
        
        // Extract categories if available
        let categories = [];
        if (analysisResponse.data.data.attributes.results) {
            const results = Object.values(analysisResponse.data.data.attributes.results);
            categories = results
                .filter(res => res.category !== 'harmless' && res.category !== 'undetected')
                .map(res => res.category);
                
            // Deduplicate
            categories = [...new Set(categories)];
        }

        return { maliciousCount, totalEngines, categories };
    } catch (error) {
        console.error('VirusTotal API error:', error.message);
        return { maliciousCount: 0, totalEngines: 0, categories: [], error: "VirusTotal API failure" };
    }
}

module.exports = { scan };
