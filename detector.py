import re
from urllib.parse import urlparse

TRUSTED = ["google.com", "paypal.com", "amazon.com", "microsoft.com", "facebook.com"]
BAD_TLDS = (".xyz", ".top", ".tk", ".ml", ".click", ".work")
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl")
RISKY_EXT = (".exe", ".scr", ".bat", ".js", ".vbs", ".docm", ".zip")
KEYWORDS = ["urgent", "verify", "suspended", "password", "confirm",
            "account locked", "winner", "click here", "act now"]


def analyze_url(url):
    """Return (score, reasons) for a URL. Higher score = more suspicious."""
    score, reasons = 0, []
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()

    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        score += 3; reasons.append("Uses an IP address instead of a domain")
    if "@" in url:
        score += 2; reasons.append("Contains '@' (can hide the real destination)")
    if len(url) > 75:
        score += 1; reasons.append("Unusually long URL")
    if host.count(".") > 3:
        score += 1; reasons.append("Too many subdomains")
    if parsed.scheme != "https":
        score += 1; reasons.append("Not using HTTPS")
    if host.endswith(BAD_TLDS):
        score += 2; reasons.append("Suspicious top-level domain")
    if host in SHORTENERS:
        score += 2; reasons.append("URL shortener hides destination")
    if "xn--" in host:
        score += 3; reasons.append("Punycode (possible look-alike characters)")

    # Spoofed domain check: "paypa1.com", "paypal.secure-login.xyz", etc.
    normalized = host.replace("0", "o").replace("1", "l").replace("3", "e")
    for real in TRUSTED:
        brand = real.split(".")[0]
        is_real = host == real or host.endswith("." + real)
        if brand in normalized and not is_real:
            score += 4; reasons.append(f"Looks like a spoof of {real}")
            break
    return score, reasons


def analyze_email(text, attachments=()):
    """Scan email text (and optional attachment names) for phishing signs."""
    score, reasons = 0, []
    lowered = text.lower()

    hits = [k for k in KEYWORDS if k in lowered]
    if hits:
        score += len(hits); reasons.append(f"Pressure/phishing words: {', '.join(hits)}")

    for f in attachments:
        if f.lower().endswith(RISKY_EXT):
            score += 3; reasons.append(f"Risky attachment: {f}")

    for url in re.findall(r"https?://[^\s\"'<>]+", text):
        s, r = analyze_url(url)
        score += s
        reasons += [f"[{url}] {x}" for x in r]
    return score, reasons


def verdict(score):
    if score >= 6: return "🚨 PHISHING"
    if score >= 3: return "⚠️ SUSPICIOUS"
    return "✅ LIKELY SAFE"


if __name__ == "__main__":
    choice = input("Scan (1) URL or (2) Email text? ")
    if choice == "1":
        score, reasons = analyze_url(input("Enter URL: "))
    else:
        score, reasons = analyze_email(input("Paste email text: "))
    print(f"\nScore: {score} -> {verdict(score)}")
    for r in reasons:
        print(" -", r)