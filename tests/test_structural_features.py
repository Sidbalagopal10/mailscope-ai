from __future__ import annotations

from app.benchmarking.structural_features import (
    extract_structural_features,
    shannon_entropy,
)


def test_regular_domain():
    result = extract_structural_features(
        "https://example.com/"
    )

    assert (
        result[
            "hostname"
        ]
        == "example.com"
    )

    assert (
        result[
            "hostname_is_ip"
        ]
        is False
    )


def test_ip_hostname():
    result = extract_structural_features(
        "http://192.0.2.50/login"
    )

    assert (
        result[
            "hostname_is_ip"
        ]
        is True
    )


def test_sensitive_login_term():
    result = extract_structural_features(
        "https://example.test/account/login"
    )

    assert (
        result[
            "sensitive_term_count"
        ]
        >= 2
    )


def test_punycode():
    result = extract_structural_features(
        "https://xn--example-9db.test/"
    )

    assert (
        result[
            "contains_punycode"
        ]
        is True
    )


def test_at_symbol():
    result = extract_structural_features(
        "https://user@example.test/"
    )

    assert (
        result[
            "contains_at_symbol"
        ]
        is True
    )


def test_entropy_nonzero():
    assert (
        shannon_entropy(
            "abcdef123456"
        )
        > 0
    )
