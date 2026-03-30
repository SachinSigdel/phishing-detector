---
title: PhishGuard
emoji: 🛡
colorFrom: blue
colorTo: cyan
sdk: docker
app_port: 7860
app_file: app.py
pinned: false
---

# 🛡️ PhishGuard — AI Phishing Email Detector

A 3-layer AI-powered phishing email detection system built with Python, scikit-learn, and Llama 3. Paste any suspicious email and get an instant risk assessment with human-readable explanations.

**Live demo:** https://phishguard-i769.onrender.com

---

## Features

- **Rule-based engine** — detects urgency language, suspicious URLs, spoofed senders
- **ML classifier** — Random Forest trained on 34,000 real emails (99% accuracy)
- **LLM reasoning** — Llama 3.3-70B via Groq explains *why* an email is suspicious
- **AI follow-up chat** — ask anything about the analyzed email
- **Single-page UI** — clean terminal-aesthetic interface, no scrolling

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.9, Flask |
| ML Model | scikit-learn (Random Forest + TF-IDF) |
| LLM | Llama 3.3-70B via Groq API |
| Frontend | HTML, CSS, Vanilla JS |
| Dataset | Enron + Phishing Email Dataset (34k emails) |

---

## Project Structure

```
phishing-detector/
├── app.py              # Flask server + API routes
├── detector.py         # Detection logic (rules + ML + LLM)
├── train_model.py      # One-time model training script
├── requirements.txt    # Python dependencies
├── .env                # API keys (not committed)
├── templates/
│   └── index.html      # Main UI
├── static/
│   ├── style.css       # Styles
│   └── app.js          # Frontend logic
└── model/
    ├── phishing_model.pkl   # Trained Random Forest model
    └── vectorizer.pkl       # TF-IDF vectorizer
```

---

## Getting Started

### 1. Clone the repo
```bash
git clone https://github.com/your-username/phishing-detector.git
cd phishing-detector
```

### 2. Create virtual environment
```bash
python3 -m venv venv
source venv/bin/activate       # Mac/Linux
# venv\Scripts\activate        # Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Set up environment variables
```bash
cp .env.example .env
```
Then edit `.env` and add your Groq API key (free at https://console.groq.com):
```
GROQ_API_KEY=your-key-here
```

### 5. Train the ML model
Download the dataset from [Kaggle](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset) and place `phishing_email.csv` in the project root, then:
```bash
python train_model.py
```
This takes 3–7 minutes and saves the model to `model/`.

### 6. Run the app
```bash
python app.py
```
Visit **http://127.0.0.1:5000**

---

## How It Works

```
Email input
    ↓
Rule-based checks     → urgency words, suspicious URLs, fake senders
    ↓
ML classifier         → TF-IDF + Random Forest (99% accuracy)
    ↓
Llama 3 reasoning     → human-readable explanation via Groq
    ↓
Blended risk score    → 0–100 with verdict + signals
```

Each layer contributes to a blended score:
- Rules: 20%
- ML model: 50%
- LLM confidence: 30%

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the web UI |
| `POST` | `/analyze` | Analyzes an email, returns JSON result |
| `POST` | `/chat` | Handles follow-up chat about the email |

### Example `/analyze` request
```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"email": "Your email text here..."}'
```

### Example response
```json
{
  "verdict": "LIKELY PHISHING",
  "score": 95,
  "color": "red",
  "summary": "High confidence this is a phishing attempt.",
  "reasons": [
    "⚠️ Urgency language: \"immediately\"",
    "🔗 Shortened/suspicious URL: http://bit.ly/...",
    "🤖 ML model confidence: 93% phishing"
  ],
  "ai_explanation": "This email impersonates PayPal...",
  "ai_verdict": "LIKELY PHISHING",
  "ai_confidence": 95
}
```

---

## Environment Variables

| Variable | Description | Required |
|---|---|---|
| `GROQ_API_KEY` | Groq API key for Llama 3 | Yes |

---

*Built as a portfolio project to demonstrate ML, NLP, and full-stack Python skills.*