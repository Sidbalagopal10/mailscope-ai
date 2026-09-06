from app.ml.url_features import extract_url_features


def test_safe_https_url():
    features = extract_url_features(
        "https://example.com/about"
    )

    assert features["uses_https"] == 1
    assert features["uses_http"] == 0
    assert features["hostname_is_ip"] == 0
    assert features["count_subdomains"] == 0


def test_ip_address_url():
    features = extract_url_features(
        "http://192.168.1.10/login"
    )

    assert features["hostname_is_ip"] == 1
    assert features["uses_http"] == 1
    assert (
        features["count_suspicious_keywords"]
        >= 1
    )


def test_suspicious_subdomain_url():
    features = extract_url_features(
        "http://paypal.account.verify.example.com/login"
    )

    assert features["count_subdomains"] >= 3
    assert (
        features["count_suspicious_keywords"]
        >= 2
    )


def test_encoded_url():
    features = extract_url_features(
        "https://example.com/%2Flogin%3Faccount"
    )

    assert (
        features["contains_encoded_characters"]
        == 1
    )


def test_url_shortener():
    features = extract_url_features(
        "https://bit.ly/example"
    )

    assert features["uses_url_shortener"] == 1
