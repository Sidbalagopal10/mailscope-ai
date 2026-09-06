from app.ml.classifier import predict_url


def test_classifier_returns_probability():
    result = predict_url(
        "https://example.com/about"
    )

    assert (
        0
        <= result[
            "phishing_probability"
        ]
        <= 1
    )

    assert result["classification"] in {
        "benign",
        "phishing",
    }


def test_suspicious_demo_url():
    result = predict_url(
        "http://paypal-account-verification."
        "example/login?user=123456"
    )

    assert (
        result[
            "phishing_probability"
        ]
        >= 0.5
    )


def test_benign_demo_url():
    result = predict_url(
        "https://python.org/docs"
    )

    assert (
        result[
            "phishing_probability"
        ]
        < 0.5
    )
