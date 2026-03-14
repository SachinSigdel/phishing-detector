import re
import joblib
import os
import numpy as np
from urllib.parse import urlparse
from groq import Groq
from dotenv import load_dotenv

# --- Load ML model at startup (not on every request) ---
MODEL_PATH = "model/phishing_model.pkl"
VECTORIZER_PATH = "model/vectorizer.pkl"

ml_model = None
ml_vectorizer = None

def load_model():
    """Load the trained model from disk."""
    global ml_model, ml_vectorizer
    if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        ml_model = joblib.load(MODEL_PATH)
        ml_vectorizer = joblib.load(VECTORIZER_PATH)
        print("✅ ML model loaded")
    else:
        print("⚠️  No ML model found — using rules only. Run train_model.py first.")

def predict_with_ml(email_text):
    """Use the trained model to predict phishing probability."""
    if ml_model is None or ml_vectorizer is None:
        return None, None
    
    # Convert the email text to the same number format we trained on
    X = ml_vectorizer.transform([email_text])
    
    # predict_proba gives us [prob_legitimate, prob_phishing]
    probabilities = ml_model.predict_proba(X)[0]
    ml_confidence = int(probabilities[1] * 100)  # phishing probability as 0-100
    ml_verdict = "PHISHING" if probabilities[1] > 0.5 else "LEGITIMATE"
    
    return ml_verdict, ml_confidence

# Load model when this file is imported
load_model()

# --- Keep all your existing constants and functions exactly as they are ---
URGENT_WORDS = [
    "urgent", "immediately", "act now", "verify your account",
    "suspended", "unusual activity", "confirm your identity",
    "click here", "limited time", "expires", "unauthorized",
    "your account has been", "security alert"
]

SUSPICIOUS_DOMAINS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co",
    "secure-login", "account-verify", "update-info"
]

def extract_urls(text):
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(pattern, text)

def check_urgency(text):
    text_lower = text.lower()
    return [word for word in URGENT_WORDS if word in text_lower]

def check_urls(text):
    urls = extract_urls(text)
    suspicious = []
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if any(sd in domain for sd in SUSPICIOUS_DOMAINS):
            suspicious.append(f"Shortened/suspicious URL: {url}")
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            suspicious.append(f"IP address instead of domain: {url}")
        lookalikes = ["paypa1", "amaz0n", "g00gle", "micros0ft", "app1e"]
        if any(fake in domain for fake in lookalikes):
            suspicious.append(f"Lookalike domain: {domain}")
    return suspicious

def check_sender(email_text):
    warnings = []
    from_match = re.search(r'[Ff]rom:.*?<(.+?)>', email_text)
    if from_match:
        actual_email = from_match.group(1)
        if re.search(r'gmail|yahoo|hotmail|outlook', actual_email):
            if re.search(r'bank|paypal|amazon|apple|microsoft|support|security',
                        email_text.lower()):
                warnings.append(f"Company impersonation via free email: {actual_email}")
    return warnings

load_dotenv()

def analyze_with_groq(email_text, rule_signals, ml_confidence):
    """Send email + existing signals to Groq for deep reasoning."""
    
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))
    
    # We give Groq context about what we already found
    signals_summary = "\n".join(rule_signals) if rule_signals else "No rule-based signals found."
    
    prompt = f"""You are a cybersecurity expert specializing in phishing email detection.

I've already run automated checks on this email and found:
- ML model phishing confidence: {ml_confidence}%
- Rule-based signals detected:
{signals_summary}

Now analyze the email yourself and provide a brief expert assessment.
Respond in this exact JSON format with no extra text:

{{
  "verdict": "SAFE" or "SUSPICIOUS" or "LIKELY PHISHING",
  "confidence": a number from 0 to 100,
  "explanation": "2-3 sentences explaining your verdict in plain English that a non-technical user can understand",
  "red_flags": ["specific red flag 1", "specific red flag 2"]
}}

Email to analyze:
---
{email_text[:3000]}
---"""

    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        model="llama-3.3-70b-versatile",
        temperature=0.1,  # low = more consistent, factual responses
        max_tokens=500,
    )
    
    import json
    response_text = chat_completion.choices[0].message.content
    
    # Strip markdown code blocks if Groq wraps it in ```json ... ```
    response_text = response_text.strip()
    if response_text.startswith("```"):
        response_text = response_text.split("```")[1]
        if response_text.startswith("json"):
            response_text = response_text[4:]
    
    return json.loads(response_text.strip())

# --- Updated analyze_email — blends ML + rules ---
def analyze_email(email_text):
    reasons = []
    rule_score = 0

    # Rule-based checks
    urgent_phrases = check_urgency(email_text)
    suspicious_urls = check_urls(email_text)
    sender_warnings = check_sender(email_text)

    if urgent_phrases:
        rule_score += len(urgent_phrases) * 15
        reasons.append(f"⚠️ Urgency language: \"{urgent_phrases[0]}\"" +
                      (f" (+{len(urgent_phrases)-1} more)" if len(urgent_phrases) > 1 else ""))
    if suspicious_urls:
        rule_score += len(suspicious_urls) * 25
        for w in suspicious_urls:
            reasons.append(f"🔗 {w}")
    if sender_warnings:
        rule_score += len(sender_warnings) * 30
        for w in sender_warnings:
            reasons.append(f"📧 {w}")

    rule_score = min(rule_score, 100)

    # ML prediction
    ml_verdict, ml_confidence = predict_with_ml(email_text)

    if ml_confidence is not None:
        # Blend: 30% rules, 70% ML (ML is more reliable)
        final_score = int(rule_score * 0.3 + ml_confidence * 0.7)
        reasons.append(f"🤖 ML model confidence: {ml_confidence}% phishing")
        detection_method = "ML + Rules"
    else:
        final_score = rule_score
        detection_method = "Rules only"

    final_score = min(final_score, 100)

    # Verdict
    if final_score < 20:
        verdict, color = "SAFE", "green"
        summary = "No phishing indicators were detected. The message appears legitimate."

    elif final_score < 45:
        verdict, color = "LOW PHISHING RISK", "yellow"
        summary = "A small number of phishing indicators were detected. Exercise caution when interacting with this message."

    elif final_score < 70:
        verdict, color = "SUSPICIOUS PHISHING RISK", "orange"
        summary = "Multiple phishing indicators were detected. Avoid clicking links or sharing sensitive information."

    else:
        verdict, color = "LIKELY PHISHING", "red"
        summary = "Strong phishing indicators were detected. This message is highly likely to be a phishing attempt."

    # --- Groq deep reasoning ---
    groq_result = None
    try:
        groq_result = analyze_with_groq(email_text, reasons.copy(), ml_confidence or rule_score)
        
        # Add Groq's specific red flags to the signals list
        for flag in groq_result.get("red_flags", []):
            reasons.append(f"🧠 {flag}")
        
        # Blend all three: rules 20%, ML 50%, Groq 30%
        if ml_confidence is not None:
            final_score = int(
                rule_score * 0.2 +
                ml_confidence * 0.5 +
                groq_result["confidence"] * 0.3
            )
        else:
            final_score = int(rule_score * 0.4 + groq_result["confidence"] * 0.6)
            
    except Exception as e:
        print(f"⚠️  Groq unavailable: {e}")
        # Fall back to ML + rules if Groq fails
        if ml_confidence is not None:
            final_score = int(rule_score * 0.3 + ml_confidence * 0.7)
        else:
            final_score = rule_score

    final_score = min(final_score, 100)

    # Verdict
    if final_score < 20:
        verdict, color = "SAFE", "green"
        summary = "No phishing indicators were detected. The message appears legitimate."

    elif final_score < 45:
        verdict, color = "LOW PHISHING RISK", "yellow"
        summary = "A small number of phishing indicators were detected. Exercise caution when interacting with this message."

    elif final_score < 70:
        verdict, color = "SUSPICIOUS PHISHING RISK", "orange"
        summary = "Multiple phishing indicators were detected. Avoid clicking links or sharing sensitive information."

    else:
        verdict, color = "LIKELY PHISHING", "red"
        summary = "Strong phishing indicators were detected. This message is highly likely to be a phishing attempt."

    return {
        "score": final_score,
        "verdict": verdict,
        "color": color,
        "summary": summary,
        "reasons": reasons if reasons else ["No specific threats identified."],
        "detection_method": detection_method,
        "ml_confidence": ml_confidence,
        # New Groq fields
        "ai_explanation": groq_result["explanation"] if groq_result else None,
        "ai_verdict": groq_result["verdict"] if groq_result else None,
    }