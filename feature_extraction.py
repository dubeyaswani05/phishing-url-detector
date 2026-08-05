"""
feature_extraction.py
----------------------
Turns a raw URL string into a fixed set of numeric "features" that a
Machine Learning model can learn from.

Why these features? Phishing URLs tend to behave differently from
legitimate ones in measurable ways - they're longer, hide the real
domain, avoid HTTPS, stuff in brand names + scary keywords, use IP
addresses instead of domain names, etc. This file encodes that domain
knowledge into numbers.
"""

import re
from urllib.parse import urlparse

# Words attackers commonly stuff into phishing URLs to create urgency
# or impersonate a trusted brand/action.
SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "bank", "signin", "password", "billing", "suspend", "limited",
    "security", "ebayisapi", "webscr", "alert", "recover"
]

# Common URL shortener domains - attackers use these to hide the real
# destination from the victim.
SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"]

IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _get_domain(url: str) -> str:
    parsed = urlparse(url if "://" in url else "http://" + url)
    return parsed.netloc.split(":")[0]  # strip port if present


def extract_features(url: str) -> dict:
    """Return a dict of named numeric features for a single URL."""
    url = url.strip()
    domain = _get_domain(url)
    parsed = urlparse(url if "://" in url else "http://" + url)
    path = parsed.path or ""

    features = {
        "url_length": len(url),
        "domain_length": len(domain),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at_symbol": url.count("@"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_subdomains": max(domain.count(".") - 1, 0),
        "has_ip_address": int(bool(IP_PATTERN.match(domain))),
        "has_https": int(url.lower().startswith("https")),
        "has_port": int(":" in domain or (":" in url.split("//")[-1].split("/")[0] and not url.lower().startswith("https"))),
        "is_shortened": int(any(s in domain for s in SHORTENERS)),
        "suspicious_word_count": sum(1 for w in SUSPICIOUS_WORDS if w in url.lower()),
        "path_length": len(path),
        "has_double_slash_redirect": int("//" in path),
    }
    return features


# The exact column order the model expects. Keeping this in one place
# guarantees training and live-prediction always use identical ordering.
FEATURE_NAMES = list(extract_features("http://example.com").keys())


# ---------------------------------------------------------------
# Visual URL breakdown + plain-English explanation
# (added for the "Visual URL Breakdown" / "Plain-English" features)
# ---------------------------------------------------------------
import html as _html
from markupsafe import Markup


def build_url_breakdown(url, feats):
    """Returns a Markup-safe HTML string with the URL split into
    colour-coded scheme / domain / path segments, with suspicious
    keywords and risky tokens highlighted inline."""
    parsed = urlparse(url if "://" in url else "http://" + url)
    scheme = _html.escape(parsed.scheme)
    domain = _html.escape(parsed.netloc)
    rest = _html.escape(parsed.path + (("?" + parsed.query) if parsed.query else ""))

    def highlight_keywords(text):
        for w in SUSPICIOUS_WORDS:
            text = re.sub(rf"(?i)({re.escape(w)})", r'<span class="hl-kw">\1</span>', text)
        return text

    domain_html = highlight_keywords(domain)
    rest_html = highlight_keywords(rest)

    if "@" in domain_html:
        domain_html = domain_html.replace("@", '<span class="hl-at">@</span>')

    domain_classes = ["url-domain"]
    if feats.get("has_ip_address"):
        domain_classes.append("hl-ip")
    elif not feats.get("has_https"):
        domain_classes.append("hl-nohttps")
    else:
        domain_classes.append("hl-ok")
    if feats.get("is_shortened"):
        domain_classes.append("hl-short")

    scheme_class = "url-scheme " + ("hl-https-ok" if feats.get("has_https") else "hl-https-bad")

    out = (
        f'<span class="{scheme_class}">{scheme}://</span>'
        f'<span class="{" ".join(domain_classes)}">{domain_html}</span>'
        f'<span class="url-path">{rest_html}</span>'
    )
    return Markup(out)


def top_reasons(feats, verdict, max_reasons=3):
    """Returns a short, plain-English explanation string built from
    the same 14 features, roughly ordered by the trained model's
    feature-importance ranking."""
    reasons = []
    if verdict == "PHISHING":
        if feats.get("has_ip_address"):
            reasons.append("domain is a raw IP address")
        if feats.get("suspicious_word_count", 0) > 0:
            n = feats["suspicious_word_count"]
            reasons.append(f"{n} suspicious keyword{'s' if n != 1 else ''} found")
        if not feats.get("has_https"):
            reasons.append("no HTTPS")
        if feats.get("num_hyphens", 0) >= 2:
            reasons.append("multiple hyphens in domain")
        if feats.get("is_shortened"):
            reasons.append("known URL shortener")
        if feats.get("num_at_symbol", 0) > 0:
            reasons.append("'@' redirect trick")
        if feats.get("has_double_slash_redirect"):
            reasons.append("'//' redirect trick in path")
        if feats.get("has_port"):
            reasons.append("custom port specified")
        if not reasons:
            reasons.append("unusual structural pattern")
    else:
        if feats.get("has_https"):
            reasons.append("uses HTTPS")
        if feats.get("suspicious_word_count", 0) == 0:
            reasons.append("no suspicious keywords")
        if not feats.get("has_ip_address"):
            reasons.append("standard domain (not a raw IP)")
        if feats.get("num_hyphens", 0) == 0:
            reasons.append("clean domain, no hyphens")
        if not reasons:
            reasons.append("matches typical legitimate URL pattern")
    return ", ".join(reasons[:max_reasons])


if __name__ == "__main__":
    # quick manual check
    for test_url in [
        "https://www.google.com/search?q=hello",
        "http://secure-login-paypal-verify123.tk/account/update",
    ]:
        print(test_url, "->", extract_features(test_url))
