# 🛡️ PhishShield AI — SIH 1454 Solution

> **Intelligent AI/ML System to Detect Phishing Domains Impersonating Genuine Look-and-Feel**

---

## 📌 Project Overview
**PhishShield AI** is a multimodal artificial intelligence system designed to combat Zero-Day phishing attacks. Unlike traditional domain blocklists that only look at static URL text, PhishShield AI acts as an automated security analyst by dynamically visiting web pages using a stealth crawler, capturing page visual layout screenshots, extracting **ResNet50 visual embeddings**, inspecting **DOM AST & obfuscated JavaScript code**, and calculating a real-time **Weighted Ensemble Risk Score (0–100%)**.

---

## 🏗️ Project Directory Layout

```
c:\SIH PROJECT\
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI entry point & API endpoints
│   │   ├── config.py                   # Configuration & weights configuration
│   │   ├── db/
│   │   │   └── vector_store.py         # Reference brand profile vector database
│   │   ├── services/
│   │   │   ├── crawler.py              # Stealth Playwright & fallback crawler
│   │   │   ├── url_analyzer.py         # Levenshtein distance & Homoglyph NLP
│   │   │   ├── vision_analyzer.py      # ResNet50 & Cosine visual similarity AI
│   │   │   ├── dom_analyzer.py         # Form action mismatch & JS obfuscation inspector
│   │   │   ├── metadata_analyzer.py    # SSL HTTPS & Security header inspector
│   │   │   └── scoring_engine.py       # Ensemble Risk Scoring Engine (0-100%)
│   │   └── utils/
│   │       └── stix_exporter.py        # STIX 2.1 Threat Report & DNS Sinkhole Exporter
│   ├── requirements.txt                # Python dependencies
│   └── seed_brand_data.py              # Seeding reference brand visual signatures
├── extension/                          # Chrome Extension (Manifest V3)
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.css
│   ├── popup.js
│   ├── content.js
│   └── background.js
├── frontend/                           # SOC Admin Operations Center Dashboard
│   ├── index.html
│   ├── styles.css
│   └── app.js
└── run_server.py                       # Single-click server launcher
```

---

## 🚀 Quick Start Guide

### Step 1: Run the Backend Server
```bash
python run_server.py
```
* **SOC Dashboard**: [http://127.0.0.1:8000/dashboard/index.html](http://127.0.0.1:8000/dashboard/index.html)
* **Swagger API Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### Step 2: Install Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle in the top-right corner).
3. Click **Load unpacked** and select the `c:\SIH PROJECT\extension` directory.
4. Pin the **PhishShield AI** icon to your browser toolbar!

---

## ⚙️ Key Technical Features

1. **Computer Vision Visual Impersonation AI**: Uses PyTorch ResNet50 dense feature embeddings and Cosine Similarity to detect stolen brand login pages (SBI, HDFC, PayPal, Google, Amazon, Netflix).
2. **DOM AST & Code Inspection**: Scans form action endpoints for cross-domain credentials post, password inputs over unencrypted HTTP, and obfuscated JavaScript (`eval`, hex encoding).
3. **Typosquatting & Homoglyph Engine**: Calculates Levenshtein edit distance and converts Unicode homographs to detect deceptive domains (`paypa1.com`, `gооgle.com`).
4. **Actionable Threat Intelligence**: Exports standardized STIX 2.1 JSON threat intelligence bundles and Pi-hole DNS sinkhole rules.
