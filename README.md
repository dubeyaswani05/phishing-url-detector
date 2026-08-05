# Phishing URL Detector (Machine Learning + Flask)

A web app that takes any URL and predicts whether it's **phishing** or
**legitimate**, using a Random Forest classifier trained on structural
features of the URL itself — no need to actually visit the site.

---

## 1. How to run it (do this before the viva, test it once!)

```bash
cd phishing-detector
pip install flask scikit-learn pandas joblib

# Only needed if you want to regenerate data/model yourself:
python3 generate_dataset.py     # builds dataset.csv (1200 labelled URLs)
python3 train_model.py          # trains model.pkl, prints accuracy

# Run the live demo:
python3 app.py
```

Open `http://127.0.0.1:5000` in your browser. Type a URL, click **Scan**.
There are also three clickable example chips on the page for a fast demo.

**New: accounts and scan history.** Anyone can scan as a guest with no
login. If you click **Sign up** (top right), create a free account, and
log in, every scan you make is automatically saved to your personal
**History** page, with live stats (Total Scans / Legitimate / Phishing
Caught). This uses a local SQLite database file (`phishing_detector.db`)
that is created automatically the first time you run `app.py` — no setup
needed. If you want a completely clean database before your demo, just
delete that file and restart the app.

### Explaining the new feature in 30 seconds

> "I added optional user accounts using Flask sessions and password
> hashing — no plaintext passwords are ever stored, only a salted hash
> via Werkzeug's `generate_password_hash`. When a logged-in user scans a
> URL, the verdict is saved to a `scan_history` table in a local SQLite
> database, linked to their user ID. The History page queries that table
> and also computes live stats — total scans, and a breakdown of
> legitimate vs phishing results — directly from the database. Guests
> can still use the scanner with zero friction; they just don't get
> persistence, which is a deliberate design choice so the tool stays
> useful even without signing up."

---

## 2. What to say in 60 seconds (your opening explanation)

> "This is a phishing URL detector. Instead of checking a URL against a
> blocklist, it extracts 14 structural features from the URL — things
> like its length, whether it uses HTTPS, whether the domain is a raw
> IP address, and how many suspicious keywords like 'verify' or 'login'
> appear in it. These features are fed into a Random Forest classifier,
> which I trained on a labelled dataset of 1,200 URLs. When I type in a
> new URL, the app extracts the same features live and the model
> predicts phishing or legitimate with a confidence score."

---

## 3. Project structure

| File | Purpose |
|---|---|
| `feature_extraction.py` | Converts a raw URL string into 14 numeric features |
| `generate_dataset.py` | Builds the labelled training dataset (`dataset.csv`) |
| `train_model.py` | Trains the Random Forest model, saves `model.pkl` |
| `app.py` | Flask web server — the live demo |
| `templates/index.html` | The demo's UI |
| `static/style.css` | Styling |

**Pipeline:** `URL → feature_extraction.py → train_model.py (offline) → model.pkl → app.py (live prediction)`

---

## 4. The 14 features (know these — this is the heart of the project)

| Feature | What it measures | Why it matters |
|---|---|---|
| `url_length` | Total characters in the URL | Phishing URLs tend to be longer (extra junk to look "official") |
| `domain_length` | Characters in the domain part | Fake domains are often padded with extra words |
| `num_dots` | Count of `.` characters | More dots can mean more (fake) subdomains |
| `num_hyphens` | Count of `-` | Attackers chain words with hyphens, e.g. `paypal-secure-login` |
| `num_at_symbol` | Count of `@` | Everything before `@` in a URL is ignored by browsers — a classic trick to disguise the real destination |
| `num_digits` | Digit count | Random numbers padded into fake domains |
| `num_subdomains` | Subdomain count | `login.security.paypal-fix.tk` has more subdomains than `paypal.com` |
| `has_ip_address` | Is the domain a raw IP? | Legitimate sites almost never show users a raw IP address |
| `has_https` | Uses HTTPS? | Most legit sites use HTTPS; many (not all) phishing pages skip it |
| `has_port` | Custom port in the URL? | Unusual for normal browsing, common in quick throwaway phishing setups |
| `is_shortened` | Known shortener domain (bit.ly etc.) | Hides the real destination from the victim |
| `suspicious_word_count` | Keywords like login/verify/secure/account | Phishing pages create urgency around login/account actions |
| `path_length` | Characters in the URL path | Long paths can hide fake "account/update/verify" chains |
| `has_double_slash_redirect` | `//` appearing inside the path | Old redirect trick to disguise the true target |

---

## 5. Why Random Forest? (likely question)

- It's an **ensemble of decision trees** — each tree votes, majority wins.
- Works well on small/medium tabular data (we have 14 numeric columns).
- No need to scale/normalize features (unlike e.g. SVM or KNN).
- It gives **feature importance** for free, so you can show the examiner
  *which* features mattered most — great for explaining the model's
  reasoning instead of treating it as a black box.

Run `python3 train_model.py` and you'll see output like:

```
suspicious_word_count   0.34   <- most predictive
has_https               0.12
domain_length            0.11
...
```

This tells you: keyword stuffing is the single strongest phishing signal
in this dataset — say this out loud, it shows you understand your own
model.

---

## 6. "Your accuracy is 100%, that's suspicious" — be ready for this

Be honest about this if asked — it's a strength, not a weakness, if you
explain it correctly:

> "The dataset is synthetically generated using rule-based patterns —
> I built it that way so the project is fully self-contained and doesn't
> depend on downloading external phishing datasets. Because the patterns
> for legit vs phishing URLs are cleanly separable by design, the model
> easily reaches 100% on this test set. In a real production system,
> you'd train on a live-collected dataset (e.g. PhishTank, OpenPhish)
> where the boundary is fuzzier, and accuracy would realistically land
> in the 90–96% range. The ML pipeline and feature engineering — which
> is the actual learning outcome here — would stay the same."

This is genuinely a strong answer because it shows you understand the
difference between a *demo dataset* and a *production dataset*.

---

## 7. Possible viva questions + short answers

**Q: Why not just use a blocklist of known phishing URLs?**
A: Blocklists can't catch brand-new phishing domains. A feature-based
ML model generalizes to URLs it has never seen before, based on
structural patterns rather than an exact match.

**Q: What's the difference between this and a deep learning approach?**
A: Deep learning (e.g. character-level CNNs/RNNs) can learn features
automatically from raw text, but needs much more data and is harder to
explain. This project uses hand-engineered features + a classical ML
model, which is simpler, faster to train, and fully explainable — every
feature has a clear security justification.

**Q: How would you improve this for production?**
A: Train on real-world phishing feeds (PhishTank/OpenPhish), add
WHOIS-based features (domain age — phishing domains are usually very
new), add SSL certificate validity checks, and retrain periodically
since phishing patterns evolve.

**Q: What's overfitting, and could that be happening here?**
A: Overfitting is when a model memorizes training data instead of
learning generalizable patterns. I limited tree depth (`max_depth=10`)
and evaluated on a held-out 20% test split specifically to check for
this — the model never sees the test URLs during training.

**Q: What does precision/recall mean in this context?**
A: Precision = of the URLs flagged as phishing, how many actually are
(false positives matter — you don't want to block legitimate sites).
Recall = of all actual phishing URLs, how many did we catch (false
negatives matter — missed phishing is a security risk). Run
`train_model.py` to show both in the classification report.

**Q: Why Flask and not a JS framework?**
A: Flask is lightweight, integrates directly with the Python ML model
(no need for a separate API layer), and is fast to set up for a focused
demo like this.

**Q: How are passwords stored — is this secure?**
A: Passwords are never stored in plain text. I use Werkzeug's
`generate_password_hash()`, which applies a salted hash (PBKDF2 by
default). On login, `check_password_hash()` verifies the entered
password against the stored hash without ever decrypting it — because
hashing is one-way, there's nothing to decrypt. This is the same
underlying approach production systems use, just without the extra
infrastructure (e.g. rate-limiting, email verification) a real product
would add.

**Q: Why SQLite instead of a bigger database like MySQL or PostgreSQL?**
A: SQLite needs no separate server process — it's a single local file,
which makes the project fully self-contained and easy to demo on any
machine with zero setup. For a small academic project with a handful of
users and a few hundred scan records, SQLite's performance is more than
sufficient; a production deployment with many concurrent users would
likely move to PostgreSQL for better concurrent-write handling.

**Q: What happens to a guest's scan if they're not logged in?**
A: It's never persisted anywhere — it exists only for the duration of
that single request/response cycle, then is discarded. This is a
deliberate privacy-friendly default: we only store data for users who
explicitly created an account.

---

## 8. Live demo script (do this in front of the professor)

1. Open the app, point at the input box.
2. Type a real, well-known site: `https://www.icicibank.com/login` → show **LEGITIMATE**, high confidence.
3. Type a crafted phishing-style URL: `http://icicibank-secure-verify9921.tk/account/update` → show **PHISHING**.
4. Point at the feature breakdown table and explain 2–3 features that drove the decision (e.g. "suspicious keyword count is 3, no HTTPS, hyphen-heavy domain").
5. Mention the confidence percentage and what it means (probability output by the Random Forest, not a hard rule).
6. If asked "what if I type a phishing URL that doesn't use any of these tricks?" — be honest: "It would likely be misclassified — that's exactly why a real system would combine this with other signals like domain age, SSL info, and live blocklists. This project demonstrates the feature-engineering + ML pipeline, not a finished commercial product."

---

## 9. Possible extensions if you have a bit more time

- Add a "domain age" feature using a WHOIS lookup library.
- Add a browser extension front-end instead of a web form.
- Log every scanned URL + verdict to a small SQLite database and show a history table.
- Swap Random Forest for Logistic Regression and compare accuracy — good talking point about model comparison.
