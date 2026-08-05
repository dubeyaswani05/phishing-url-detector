"""
app.py
------
Flask web app for the Phishing URL Detector, with optional user
accounts. Anyone can scan a URL, logged in or as a guest.

Run with: python3 app.py
Then open: http://127.0.0.1:5000
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import joblib
import pandas as pd
import os

from feature_extraction import extract_features, FEATURE_NAMES, build_url_breakdown, top_reasons
import database as db

app = Flask(__name__)
app.secret_key = "iet-project-demo-secret-key-2026"  # fine for a local demo; use env var in production

model = joblib.load("model.pkl")
db.init_db()

FEATURE_LABELS = {
    "url_length": "Total URL length",
    "domain_length": "Domain length",
    "num_dots": "Number of dots",
    "num_hyphens": "Number of hyphens",
    "num_at_symbol": "@ symbol present",
    "num_digits": "Digit count",
    "num_subdomains": "Subdomain count",
    "has_ip_address": "Domain is raw IP",
    "has_https": "Uses HTTPS",
    "has_port": "Custom port specified",
    "is_shortened": "Known URL shortener",
    "suspicious_word_count": "Suspicious keywords found",
    "path_length": "Path length",
    "has_double_slash_redirect": "// redirect trick in path",
}


def current_user():
    """Returns the logged-in user's row, or None if browsing as a guest."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.get_user_by_id(user_id)


@app.context_processor
def inject_user():
    return {"current_user": current_user()}


def run_prediction(url):
    feats = extract_features(url)
    X = pd.DataFrame([feats])[FEATURE_NAMES]
    pred = model.predict(X)[0]
    proba = model.predict_proba(X)[0]
    confidence = round(proba[pred] * 100, 1)
    verdict = "PHISHING" if pred == 1 else "LEGITIMATE"
    features = [(FEATURE_LABELS[k], feats[k]) for k in FEATURE_NAMES]
    breakdown = build_url_breakdown(url, feats)
    reason = top_reasons(feats, verdict)
    return verdict, confidence, features, breakdown, reason


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            verdict, confidence, features, breakdown, reason = run_prediction(url)
            result = {
                "url": url,
                "verdict": verdict,
                "is_phishing": verdict == "PHISHING",
                "confidence": confidence,
                "features": features,
                "breakdown": breakdown,
                "reason": reason,
            }

    return render_template("index.html", result=result)


# ── Bulk scan ──────────────────────────────────────────────────
@app.route("/bulk", methods=["GET", "POST"])
def bulk():
    results = []
    error = None
    if request.method == "POST":
        # Accept either a pasted textarea OR an uploaded CSV file
        raw_text = request.form.get("urls", "").strip()
        file = request.files.get("csvfile")

        lines = []
        if file and file.filename:
            try:
                content = file.read().decode("utf-8", errors="ignore")
                lines = [l.strip() for l in content.splitlines() if l.strip()]
            except Exception:
                error = "Could not read the uploaded file."
        elif raw_text:
            lines = [l.strip() for l in raw_text.splitlines() if l.strip()]

        if len(lines) > 200:
            error = "Maximum 200 URLs per bulk scan."
            lines = []

        for line in lines:
            # skip CSV headers or comment lines
            if line.lower().startswith("url") or line.startswith("#"):
                continue
            url = line.split(",")[0].strip()   # take first column if CSV
            if not url:
                continue
            try:
                verdict, confidence, _, breakdown, reason = run_prediction(url)
                results.append({
                    "url": url,
                    "verdict": verdict,
                    "is_phishing": verdict == "PHISHING",
                    "confidence": confidence,
                    "breakdown": breakdown,
                    "reason": reason,
                })
            except Exception:
                results.append({
                    "url": url, "verdict": "ERROR", "is_phishing": False,
                    "confidence": 0, "breakdown": url, "reason": "Could not parse this URL.",
                })

    phishing_count = sum(1 for r in results if r["is_phishing"])
    return render_template("bulk.html", results=results, error=error,
                           phishing_count=phishing_count)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not username or not password:
            flash("Username and password are required.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif len(password) < 4:
            flash("Password must be at least 4 characters.", "error")
        else:
            password_hash = generate_password_hash(password)
            if db.create_user(username, password_hash):
                flash("Account created. Please log in.", "success")
                return redirect(url_for("login"))
            else:
                flash("That username is already taken.", "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = db.get_user_by_username(username)
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("index"))
        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
