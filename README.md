# 🛡️ ShieldScan — URL Security Analyzer

ShieldScan is a full-stack **AI-Powered URL Threat Intelligence Platform** built with **Node.js (Express)**, **Vanilla HTML/CSS/JS**, and multiple security intelligence APIs. It provides deep security analysis, phishing detection, and a human-readable AI explanation for any URL.

## 🚀 Key Features

*   **Google Safe Browsing & VirusTotal Integration**: Deep scans against the world's leading threat databases.
*   **Rule-Based Heuristics**: Extracts 8 specific URL features including HTTPS status, suspicious keywords, and TLD risk.
*   **Gemini AI Explanation**: Generates clear, non-technical explanations for Why a site is safe or unsafe.
*   **Legal Estimation**: Predicts the legality of the site content based on behavioral patterns.
*   **Premium Cybersecurity UI**: Stunning dark-mode interface with scan animations and historical reports.

## 📁 Project Structure

```bash
url-security-analyzer/
├── backend/
│   ├── routes/          # API Route (/api/analyze)
│   ├── services/        # Third-party API integrations (SafeBrowsing, VT, Gemini)
│   ├── utils/           # Scorer and utility functions
│   ├── server.js        # Express Entry Point
│   └── .env             # API Credentials
└── frontend/            # Vanilla JS/CSS/HTML Frontend
```

## 🛠️ Installation & Setup

### 1. Prerequisites
*   Node.js (v18.0.0 or higher)
*   Google Cloud Account (for Safe Browsing & Gemini)
*   VirusTotal Account (for VT API)

### 2. Get Your API Keys
You will need the following API keys:
1.  **Google Safe Browsing Key**: Get from [Google Cloud Console](https://console.cloud.google.com/).
2.  **VirusTotal API Key**: Register at [VirusTotal](https://www.virustotal.com/gui/join-us) and find your key in 'Settings'.
3.  **Gemini API Key**: Get from [Google AI Studio](https://aistudio.google.com/).

### 3. Build & Run
```bash
# Clone or navigate to the directory
cd url-security-analyzer/backend

# Install dependencies
npm install

# Configure environment variables
# Edit backend/.env and add your API keys
PORT=3000
GOOGLE_SAFE_BROWSING_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
GEMINI_API_KEY=your_key_here

# Start the server
node server.js
```

Open your browser at `http://localhost:3000`.

## 📡 API Reference

### POST `/api/analyze`
Send a URL to get a comprehensive security scan.

**Request Body:**
```json
{ "url": "https://example.com" }
```

**Response Sample:**
```json
{
  "url": "https://example.com",
  "score": 90,
  "level": "SAFE",
  "status": "Safe",
  "phishingProbability": 10,
  "threats": [],
  "virusTotal": { ... },
  "urlFeatures": { ... },
  "safeBrowsing": { ... },
  "legalEstimation": "Likely Legal",
  "explanation": "..."
}
```

## ⚠️ Disclaimer
*   ShieldScan is for informational purposes only. No security tool is 100% accurate.
*   The **Legal Estimation** is an AI baseline and does not constitute legal advice.
*   **Rate Limits**: VirusTotal's free tier allows 4 requests per minute.

---
Built with ❤️ by Antigravity AI
