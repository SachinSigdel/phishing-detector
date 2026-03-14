from flask import Flask, render_template, request, jsonify
from detector import analyze_email
from groq import Groq
from dotenv import load_dotenv
import os

load_dotenv()
app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    email_text = data.get("email", "")

    if not email_text.strip():
        return jsonify({"error": "No email text provided"}), 400

    result = analyze_email(email_text)
    return jsonify(result)

@app.route("/chat", methods=["POST"])
def chat():
    """
    Handles follow-up questions about the analyzed email.
    Receives the full conversation history and returns the next AI reply.
    """
    data = request.get_json()
    history = data.get("history", [])

    if not history:
        return jsonify({"error": "No conversation history provided"}), 400

    try:
        client = Groq(api_key=os.getenv("GROQ_API_KEY"))

        # System prompt gives the AI its role and constraints
        system_prompt = """You are PhishGuard AI, a cybersecurity expert specializing in phishing email analysis.
You have already analyzed an email and have full context about it.
Answer follow-up questions clearly and concisely in plain English.
Keep responses focused, helpful, and under 4 sentences unless more detail is needed.
Never make up details not present in the email or analysis."""

        # Build messages for Groq — system + full history
        messages = [{"role": "system", "content": system_prompt}] + history

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=messages,
            temperature=0.4,
            max_tokens=400,
        )

        reply = response.choices[0].message.content
        return jsonify({"reply": reply})

    except Exception as e:
        return jsonify({"error": str(e), "reply": f"Sorry, I encountered an error: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True)