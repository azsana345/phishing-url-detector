import pandas as pd
import tldextract
import re
import xgboost as xgb
import pickle
import socket
import whois
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import os

# Set network timeout for WHOIS lookups
socket.setdefaulttimeout(5)

# --- Feature extraction ---
def extract_features(url):
    features = {}
    features["url_length"] = len(url)
    features["has_ip"] = 1 if re.search(r"(?:\d{1,3}\.){3}\d{1,3}", url) else 0
    features["has_at"] = 1 if "@" in url else 0

    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'account']
    features["suspicious_words"] = 1 if any(word in url.lower() for word in suspicious_keywords) else 0

    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    features["domain_length"] = len(domain)
    features["uses_https"] = 1 if url.startswith("https://") else 0

    shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly']
    features["is_shortened"] = 1 if any(s in url for s in shorteners) else 0

    # ⛔ WHOIS feature disabled due to timeout issues
    features["domain_age_days"] = 0

    return features

# --- Model loading/saving ---
MODEL_PATH = "model.pkl"

def train_and_save_model():
    print("📚 Training new model...")

    df = pd.read_csv("combined_dataset.csv")
    X = pd.DataFrame([extract_features(url) for url in df["url"]])
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    model = xgb.XGBClassifier(use_label_encoder=False, eval_metric='logloss')
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("🚀 XGBoost Accuracy:", accuracy_score(y_test, y_pred))
    print("\n📊 Classification Report:")
    print(classification_report(y_test, y_pred))

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)

    print(f"✅ Model saved to {MODEL_PATH}")
    return model

# Load or train model
if os.path.exists(MODEL_PATH):
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    print("📦 Loaded model from model.pkl")
else:
    model = train_and_save_model()

# --- Prediction for web app ---
def predict_url(url):
    features = extract_features(url)
    df = pd.DataFrame([features])
    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0][prediction]
    return prediction, probability
