from detector import analyze_url, analyze_email, verdict


def test_safe_url():
    score, _ = analyze_url("https://www.google.com")
    assert verdict(score) == "✅ LIKELY SAFE"


def test_spoofed_url():
    score, _ = analyze_url("http://paypa1-secure-login.xyz/verify")
    assert verdict(score) == "🚨 PHISHING"


def test_phishing_email():
    text = "URGENT: verify your password at http://amaz0n-support.top/login"
    score, _ = analyze_email(text)
    assert score >= 6