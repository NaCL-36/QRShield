import base64
import difflib
import ipaddress
import re
from urllib.parse import parse_qs, unquote, urlparse

import tldextract
import validators

from utils import normalize_url, status_from_score


SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "rb.gy", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly"}
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "bank", "wallet", "gift", "reward", "free", "update",
    "password", "confirm", "payment", "signin", "account", "reset", "support", "auth"
}
KNOWN_DOMAINS = [
    "paypal.com", "google.com", "microsoft.com", "amazon.com", "facebook.com", "instagram.com", "apple.com"
]
ENCODED_PATTERNS = ("%20", "%3D", "%2F", "%2E", "%3A", "%40", "%5C")


def _host(parsed):
    return (parsed.hostname or "").lower().strip(".")


def _registered_domain(hostname):
    extracted = tldextract.extract(hostname)
    if not extracted.domain or not extracted.suffix:
        return hostname
    return f"{extracted.domain}.{extracted.suffix}".lower()


def _is_ip(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _base64_tokens(text):
    tokens = re.findall(r"[A-Za-z0-9+/]{18,}={0,2}", text or "")
    found = []
    for token in tokens:
        try:
            padded = token + "=" * (-len(token) % 4)
            decoded = base64.b64decode(padded, validate=True)
            if len(decoded) >= 8:
                found.append(token[:32])
        except Exception:
            continue
    return found


def _add_issue(issues, title, status, severity, detail, recommendation, points):
    issues.append({
        "title": title,
        "status": status,
        "severity": severity,
        "detail": detail,
        "recommendation": recommendation,
        "points": points,
    })


def analyze_content(content):
    normalized = normalize_url(content)
    parsed = urlparse(normalized)
    hostname = _host(parsed)
    domain = _registered_domain(hostname) if hostname else ""
    issues = []
    checks = []
    score = 0
    is_url = bool(validators.url(normalized))

    if not content.strip():
        _add_issue(issues, "Empty QR payload", "Failed", "High", "The QR code did not contain readable content.", "Do not trust this QR code.", 80)
    elif not is_url:
        checks.append({"name": "URL Format", "result": "Notice", "detail": "The QR code contains text or non-web content."})
        score += 10
    else:
        checks.append({"name": "URL Format", "result": "Passed", "detail": "The QR code contains a valid URL."})

    if is_url:
        if parsed.scheme.lower() != "https":
            _add_issue(issues, "HTTPS verification", "Failed", "High", "The link does not use HTTPS encryption.", "Avoid entering passwords or payment details on this site.", 25)
        else:
            checks.append({"name": "HTTPS", "result": "Passed", "detail": "The URL uses encrypted HTTPS."})

        if hostname and _is_ip(hostname):
            _add_issue(issues, "IP address URL", "Detected", "High", "The URL uses a raw IP address instead of a normal domain name.", "Treat this as suspicious unless you fully trust the source.", 25)
        else:
            checks.append({"name": "IP Address", "result": "Passed", "detail": "No raw IP address host was detected."})

        if domain in SHORTENERS:
            _add_issue(issues, "Shortened URL", "Detected", "Medium", "The link hides its final destination behind a URL shortener.", "Expand the link or verify it with a trusted service before visiting.", 18)
        else:
            checks.append({"name": "Shortened URL", "result": "Passed", "detail": "No common URL shortener was detected."})

        lowered_url = normalized.lower()
        found_keywords = sorted(keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in lowered_url)
        if found_keywords:
            _add_issue(issues, "Suspicious keywords", "Found", "Medium", f"The URL contains terms often used in phishing: {', '.join(found_keywords)}.", "Verify the sender and domain before opening the link.", min(22, 6 + len(found_keywords) * 4))
        else:
            checks.append({"name": "Suspicious Keywords", "result": "Passed", "detail": "No common phishing keywords were found."})

        if len(normalized) > 120:
            _add_issue(issues, "Long URL", "Detected", "Low", "The URL is unusually long, which can be used to hide malicious destinations.", "Inspect the domain carefully before visiting.", 10)
        else:
            checks.append({"name": "URL Length", "result": "Passed", "detail": "The URL length is within a normal range."})

        encoded_hits = [pattern for pattern in ENCODED_PATTERNS if pattern.lower() in lowered_url]
        if encoded_hits or unquote(normalized) != normalized:
            _add_issue(issues, "Encoded characters", "Found", "Medium", "The URL contains encoded characters that can obscure its real destination.", "Decode and review the full URL before opening it.", 12)
        else:
            checks.append({"name": "Encoded Characters", "result": "Passed", "detail": "No risky URL encoding was detected."})

        base64_hits = _base64_tokens(normalized)
        if base64_hits:
            _add_issue(issues, "Base64-like content", "Found", "Medium", "The URL contains long encoded-looking text that may hide tracking or redirect data.", "Be cautious with links that obscure destination data.", 10)
        else:
            checks.append({"name": "Base64 Pattern", "result": "Passed", "detail": "No clear Base64 pattern was detected."})

        if domain:
            for known in KNOWN_DOMAINS:
                similarity = difflib.SequenceMatcher(None, domain, known).ratio()
                if domain != known and similarity >= 0.78:
                    _add_issue(issues, "Possible fake domain", "Detected", "High", f"The domain '{domain}' looks similar to '{known}'.", "Do not sign in or enter sensitive data unless the domain is verified.", 30)
                    break
            else:
                checks.append({"name": "Typosquatting", "result": "Passed", "detail": "No close match to protected well-known domains was found."})

        query = parse_qs(parsed.query)
        if any(key.lower() in {"redirect", "url", "next", "target", "return"} for key in query):
            _add_issue(issues, "Redirect parameter", "Detected", "Medium", "The URL includes a redirect-style parameter that may forward users elsewhere.", "Open only after confirming the final destination.", 12)

    score += sum(issue["points"] for issue in issues)
    score = max(0, min(100, score))
    status = status_from_score(score)
    recommendation = {
        "Safe": "The QR code appears low risk. Still verify the page before sharing sensitive information.",
        "Suspicious": "Proceed carefully. Verify the source and inspect the destination before visiting.",
        "Dangerous": "Do not visit this website or enter personal information. Use an official app or manually type the known domain.",
    }[status]

    return {
        "original_content": content,
        "normalized_url": normalized if is_url else "",
        "is_url": is_url,
        "host": hostname,
        "domain": domain,
        "score": score,
        "status": status,
        "recommendation": recommendation,
        "issues": issues,
        "checks": checks,
    }
