from __future__ import annotations

from app.domain_structure.structure_engine import (
    analyze_structure,
)
from app.domain_structure.fusion_adapter import (
    structure_evidence,
)


def test_normal_short_domain_is_low():
    result = analyze_structure(
        "https://example.com/"
    )

    assert (
        result[
            "score"
        ]
        < 18
    )


def test_complex_login_url_scores_higher():
    normal = analyze_structure(
        "https://example.com/"
    )

    suspicious = analyze_structure(
        "http://secure-login-account."
        "example-verification.test/"
        "account/login"
    )

    assert (
        suspicious[
            "score"
        ]
        > normal[
            "score"
        ]
    )


def test_raw_ip_is_strong_signal():
    result = analyze_structure(
        "http://192.0.2.50/login"
    )

    names = {
        item[
            "name"
        ]
        for item in result[
            "findings"
        ]
    }

    assert (
        "raw_ip_hostname"
        in names
    )


def test_long_url_alone_not_high():
    value = (
        "https://example.com/"
        + "documentation/"
        * 5
    )

    result = analyze_structure(
        value
    )

    assert (
        result[
            "score"
        ]
        < 35
    )


def test_structure_adapter_returns_evidence():
    value = (
        "http://secure-account-login-"
        "verification.example.test/"
        "login"
    )

    evidence = structure_evidence(
        value
    )

    assert evidence
