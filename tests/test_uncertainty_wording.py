from app.detection.hybrid_detector import (
    analyze_url_hybrid,
    determine_risk_level,
)


def test_guarded_risk_level():
    assert (
        determine_risk_level(20)
        == "guarded"
    )

    assert (
        determine_risk_level(34)
        == "guarded"
    )


def test_unknown_clean_domain_is_needs_review():
    result = analyze_url_hybrid(
        "https://small-university.so/admissions"
    )

    assert result[
        "final_score"
    ] <= 34

    assert (
        result["classification"]
        == "needs_review"
    )

    assert (
        result["risk_level"]
        == "guarded"
    )

    assert (
        result["domain_reputation"]
        == "unknown"
    )

    assert (
        result["confidence_level"]
        in {
            "low",
            "medium",
        }
    )

    assert not result[
        "is_phishing"
    ]


def test_linkedin_remains_likely_legitimate():
    result = analyze_url_hybrid(
        "https://www.linkedin.com/jobs/"
    )

    assert (
        result["classification"]
        == "likely_legitimate"
    )

    assert (
        result["domain_reputation"]
        == "conditionally_trusted"
    )


def test_impersonation_remains_phishing():
    result = analyze_url_hybrid(
        "https://linkedln-login.example.com/verify"
    )

    assert (
        result["classification"]
        == "likely_phishing"
    )

    assert result[
        "is_phishing"
    ]
