from app.services.risk_engine import analyze_url


def test_safe_google_url():
    result = analyze_url("https://www.google.com")

    assert result.severity == 0.0
    assert result.risk_level == "LOW"
    assert result.is_suspicious is False


def test_fake_paypal_url():
    result = analyze_url(
        "http://paypal-login-security.example.com/verify-account"
    )

    assert result.severity >= 5
    assert result.is_suspicious is True
    assert any(
        "brand impersonation" in reason.lower()
        for reason in result.reasons
    )


def test_ip_address_url():
    result = analyze_url("http://192.168.1.50/login")

    assert result.severity >= 5
    assert any(
        "IP address" in reason
        for reason in result.reasons
    )


def test_url_shortener():
    result = analyze_url("https://bit.ly/verify-account")

    assert result.severity > 0
    assert any(
        "shortening service" in reason
        for reason in result.reasons
    )
