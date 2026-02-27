# ⚠️ IMPORTANT: Security Warning - Do Not Commit API Keys!

## Before uploading to GitHub

**NEVER commit your `.env` file** - it contains your live API keys!

The `.env` file is already in `.gitignore` (you need to add this), but please verify:

```bash
# Make sure .env is NOT tracked by git
echo ".env" >> .gitignore
echo "venv/" >> .gitignore
echo "__pycache__/" >> .gitignore
echo "*.pyc" >> .gitignore
```

---

# Threat Intel Mini Aggregator - README

## Overview

Threat Intel Mini Aggregator is a localhost web-based Threat Intelligence Dashboard designed for cybersecurity students and SOC analysts. It allows you to investigate:

- **File Hashes** (SHA256)
- **IP Addresses**
- **Domains**

The system integrates with two leading threat intelligence APIs:
- **MalwareBazaar** - Free malware sample database
- **VirusTotal** - Multi-antivirus scanning service

### Features

- Auto-detection of indicator type (hash/IP/domain)
- Risk scoring engine with threat level assessment
- Correlation engine to normalize data from multiple sources
- Professional SOC-style dark theme UI
- Detection visualization with Chart.js
- Raw JSON data export for analysis

---

## Setup Instructions for Users

### 1. Clone the Repository

```bash
git clone <repository-url>
cd threat-intel-dashboard
```

### 2. Create Virtual Environment

```bash
# Linux/Mac
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure API Keys

You need your own API keys to use this project:

#### VirusTotal API Key (Required)

1. Go to [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Create a free account
3. Navigate to API → API Key
4. Copy your API key

#### MalwareBazaar (Optional - No key required for basic use)

MalwareBazaar is free and doesn't require an API key for basic queries.

#### Create Your Configuration

```bash
# Copy the example file
cp .env.example .env
```

Edit the `.env` file and add your VirusTotal API key:

```env
# .env file (DO NOT SHARE THIS FILE)
VT_API_KEY=your_virustotal_api_key_here
MB_API_KEY=  # Leave empty - not required

FLASK_DEBUG=False
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
```

### 5. Run the Application

```bash
python app.py
```

### 6. Access the Dashboard

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## How to Use

### Analyzing an Indicator

1. **Select Indicator Type** - Choose Hash, IP, or Domain (or use Auto-Detect)
2. **Enter the Value** - Paste your indicator
3. **Click "Analyze"** - The system will query both APIs
4. **View Results** - See risk score, detection stats, and technical details

### Sample Indicators to Test

| Type | Value | Description |
|------|-------|-------------|
| Hash | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Empty file hash |
| IP | `8.8.8.8` | Google DNS |
| IP | `1.1.1.1` | Cloudflare DNS |
| Domain | `example.com` | Example domain |

---

## Architecture

```
User Browser
     │
     ▼
Flask Web Server (app.py)
     │
     ├── Input Validation
     │
     ▼
Service Layer
     ├── MalwareBazaar Service
     └── VirusTotal Service
     │
     ▼
Correlation Engine (normalizes data)
     │
     ▼
Risk Scoring Engine (calculates threat level)
     │
     ▼
UI Render (HTML/CSS/JS)
```

---

## Risk Scoring Logic

| Condition | Points |
|-----------|--------|
| VT malicious detections > 30 | +3 |
| Malware family identified | +2 |
| Ransomware tag detected | +3 |
| Suspicious detections > 10 | +1 |

### Risk Levels

- **LOW** (Score 0-2): Clean or minor indicators
- **MEDIUM** (Score 3-5): Requires attention
- **HIGH** (Score 6+): Immediate investigation recommended

---

## Security Notes

- This tool is for **educational and defensive purposes only**
- Always verify threat intelligence with multiple sources
- API keys are stored locally - never committed to version control
- Rate limits apply ( VirusTotal: 4 requests/minute free tier)

---

## Troubleshooting

### "VirusTotal API key not configured"

You need to add your API key to the `.env` file. See Step 4 above.

### "Rate limit exceeded"

VirusTotal free tier has limits. Wait a minute and try again.

### "Request timeout"

Check your internet connection and try again.

---

## Future Improvements

- [ ] Add more threat intel sources (AlienVault OTX, AbuseIPDB)
- [ ] Implement caching to reduce API calls
- [ ] Add database for query history
- [ ] Export reports to PDF/JSON
- [ ] User authentication

---

## License

Educational Use Only | For Learning & Defensive Security

---

## Disclaimer

This tool is for educational purposes. Always follow responsible disclosure practices and respect API terms of service.
