# Phishing URL Detector

A Flask-based web application that detects phishing URLs using a Random Forest machine learning classifier trained on 14 URL-based features. Built as part of my Industrial Exposure Training internship at Nitroware Technologies Pvt. Ltd.

## Features

**v1 — Core Detection**
- Random Forest ML model analyzing 14 URL-based features
- Real-time URL classification (legitimate vs phishing)

**v2 — User System**
- SQLite-based user authentication
- Scan history dashboard for logged-in users

**v3 — Advanced Analysis**
- Visual URL breakdown showing risk indicators
- Bulk CSV scanner — analyze up to 200 URLs at once
- CSV export of scan results

## Tech Stack
- **Backend:** Python, Flask
- **Machine Learning:** scikit-learn (Random Forest Classifier)
- **Database:** SQLite
- **Frontend:** HTML, CSS

## Dataset
- Synthetic training dataset of 1,200 URLs
- 40-URL demo dataset for testing

## How It Works
The model extracts 14 features from a given URL (such as URL length, presence of special characters, domain-based indicators, and structural patterns) and classifies it as legitimate or phishing using a trained Random Forest classifier.

## Getting Started

```bash
git clone https://github.com/dubeyaswani05/phishing-url-detector.git
cd phishing-url-detector
pip install -r requirements.txt
python app.py
```

## Author
**Aswani Dubey**
BCA Final Year Student, Sri Krishna Arts and Science College (Autonomous), Coimbatore
[LinkedIn](https://www.linkedin.com/in/aswanidubey05)
