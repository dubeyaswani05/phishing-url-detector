"""
generate_dataset.py
--------------------
Builds a labelled training dataset of URLs entirely offline, by
generating realistic legitimate and phishing-style URLs from
patterns, then extracting features for each one.

Label: 1 = phishing, 0 = legitimate

This avoids depending on any external dataset download - everything
needed to reproduce the project runs from this single script.
"""

import random
import csv
from feature_extraction import extract_features, FEATURE_NAMES

random.seed(42)

LEGIT_DOMAINS = [
    "google.com", "youtube.com", "wikipedia.org", "github.com",
    "amazon.in", "flipkart.com", "microsoft.com", "apple.com",
    "linkedin.com", "instagram.com", "stackoverflow.com", "nptel.ac.in",
    "irctc.co.in", "icicibank.com", "hdfcbank.com", "swiggy.com",
    "zomato.com", "paytm.com", "wikipedia.com", "bbc.com", "nytimes.com",
    "leetcode.com", "coursera.org", "khanacademy.org", "geeksforgeeks.org",
]

LEGIT_PATHS = [
    "", "/", "/search?q=python", "/login", "/about", "/products/123",
    "/watch?v=abc123", "/in/profile", "/article/2024/news",
    "/course/machine-learning", "/cart", "/orders", "/profile/settings",
]

PHISHING_BRANDS = [
    "paypal", "icicibank", "hdfcbank", "amazon", "facebook", "instagram",
    "netflix", "irctc", "sbi", "google", "microsoft", "apple",
]

PHISHING_TLDS = [".tk", ".xyz", ".ml", ".ga", ".cf", ".top", ".info", ".loan"]

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "billing", "suspend", "limited", "alert", "recover",
]


def random_legit_url():
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    scheme = "https"
    sub = random.choice(["www.", ""])
    return f"{scheme}://{sub}{domain}{path}"


def random_phishing_url():
    brand = random.choice(PHISHING_BRANDS)
    word1 = random.choice(SUSPICIOUS_WORDS)
    word2 = random.choice(SUSPICIOUS_WORDS)
    style = random.randint(0, 4)
    scheme = random.choice(["http", "http", "https"])  # mostly http

    if style == 0:
        # brand-hyphen-word + random digits + suspicious tld
        host = f"{brand}-{word1}-{random.randint(10,9999)}{random.choice(PHISHING_TLDS)}"
        path = f"/{word2}/{random.choice(['account','update','reset'])}"
    elif style == 1:
        # raw IP address pretending to be a bank/site
        host = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"
        path = f"/{brand}/{word1}.php"
    elif style == 2:
        # subdomain trick: brand.something.tld
        host = f"{brand}.{word1}-{word2}{random.choice(PHISHING_TLDS)}"
        path = f"/{word2}"
    elif style == 3:
        # @ symbol trick
        host = f"{word1}{random.choice(PHISHING_TLDS)}"
        path = f"@{brand}.com/{word2}"
        return f"{scheme}://{host}/{path}"
    else:
        # long random subdomain chain
        host = f"{word1}.{word2}.{brand}-{random.randint(1,999)}{random.choice(PHISHING_TLDS)}"
        path = f"/{random.choice(['secure','confirm'])}/{random.randint(1000,9999)}"

    return f"{scheme}://{host}{path}"


def build_dataset(n_per_class=600):
    rows = []
    for _ in range(n_per_class):
        url = random_legit_url()
        feats = extract_features(url)
        feats["label"] = 0
        feats["url"] = url
        rows.append(feats)

    for _ in range(n_per_class):
        url = random_phishing_url()
        feats = extract_features(url)
        feats["label"] = 1
        feats["url"] = url
        rows.append(feats)

    random.shuffle(rows)
    return rows


def main():
    rows = build_dataset(n_per_class=600)
    fieldnames = FEATURE_NAMES + ["label", "url"]
    with open("dataset.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to dataset.csv")
    print(f"Legit: {sum(1 for r in rows if r['label']==0)}, "
          f"Phishing: {sum(1 for r in rows if r['label']==1)}")


if __name__ == "__main__":
    main()
