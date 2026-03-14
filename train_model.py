import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os

print("📂 Loading dataset...")
df = pd.read_csv("phishing_email.csv")

# Quick look at what we have
print(f"   Total emails: {len(df)}")
print(f"   Phishing:     {df['label'].sum()}")
print(f"   Legitimate:   {len(df) - df['label'].sum()}")

# Drop any rows with missing email text
df = df.dropna(subset=["text_combined"])
print(f"   After cleaning: {len(df)} emails\n")

# --- STEP A: Convert emails to numbers ---
# ML models can't read text — we need to convert it to numbers first.
# TF-IDF does this: it counts words, but weighs rare words higher than
# common ones ("the", "and" are everywhere — not useful signals).

print("🔢 Converting text to numbers (TF-IDF)...")
vectorizer = TfidfVectorizer(
    max_features=10000,   # only keep the 10,000 most useful words
    stop_words="english", # ignore common words like "the", "a", "is"
    ngram_range=(1, 2),   # look at single words AND pairs ("click here", "act now")
)

X = vectorizer.fit_transform(df["text_combined"])
y = df["label"]
print(f"   Matrix shape: {X.shape}  (emails × word-features)\n")

# --- STEP B: Split into training and test sets ---
# We train on 80% of data, test on the remaining 20% it's never seen.
# This tells us how well it'll perform on real emails.

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,      # 20% for testing
    random_state=42,    # fixed seed = reproducible results
    stratify=y          # keep same phishing/legit ratio in both splits
)

print(f"📊 Training on {X_train.shape[0]} emails, testing on {X_test.shape[0]}\n")

# --- STEP C: Train the model ---
# Random Forest = builds many decision trees and votes on the answer.
# Great for text classification — fast, accurate, hard to overfit.

print("🌲 Training Random Forest model...")
model = RandomForestClassifier(
    n_estimators=100,   # 100 decision trees vote together
    n_jobs=-1,          # use all CPU cores (faster)
    random_state=42
)
model.fit(X_train, y_train)
print("   Training complete!\n")

# --- STEP D: Evaluate ---
print("📈 Evaluating on test set...")
y_pred = model.predict(X_test)

print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

# Confusion matrix — shows false positives and false negatives
cm = confusion_matrix(y_test, y_pred)
print("Confusion Matrix:")
print(f"   True Legitimate:  {cm[0][0]}  |  False Phishing: {cm[0][1]}")
print(f"   False Legitimate: {cm[1][0]}  |  True Phishing:  {cm[1][1]}\n")

# --- STEP E: Save the model ---
os.makedirs("model", exist_ok=True)
joblib.dump(model, "model/phishing_model.pkl")
joblib.dump(vectorizer, "model/vectorizer.pkl")

print("💾 Model saved to model/phishing_model.pkl")
print("💾 Vectorizer saved to model/vectorizer.pkl")
print("\n✅ Done! Run python app.py to use your trained model.")