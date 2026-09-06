from app.detection.brand_intelligence import (
    is_known_official_domain,
)
from app.detection.hybrid_detector import (
    analyze_url_hybrid,
)
from app.ml.classifier import (
    predict_url,
    reload_url_classifier,
)


def setup_module():
    reload_url_classifier()


def test_linkedin_jobs_is_not_phishing():
    result = analyze_url_hybrid(
        "https://www.linkedin.com/jobs/"
    )

    assert result[
        "final_score"
    ] < 35

    assert not result[
        "is_phishing"
    ]

    assert result[
        "official_domain_evidence"
    ][
        "recognized"
    ]


def test_python_docs_is_not_phishing():
    result = predict_url(
        "https://python.org/docs"
    )

    assert result[
        "phishing_probability"
    ] < 0.5

    assert result[
        "official_domain_guardrail"
    ]


def test_official_bank_homepage_is_not_phishing():
    result = analyze_url_hybrid(
        "https://www.bankofamerica.com/"
    )

    assert result[
        "final_score"
    ] < 35

    assert not result[
        "is_phishing"
    ]


def test_unknown_domain_is_neutral():
    assert not is_known_official_domain(
        "small-university.so"
    )

    result = analyze_url_hybrid(
        "https://small-university.so/admissions"
    )

    assert result[
        "official_domain_evidence"
    ][
        "unknown_domain_penalty"
    ] == 0


def test_linkedin_typo_remains_dangerous():
    result = analyze_url_hybrid(
        "https://linkedln-login.example.com/verify"
    )

    assert result[
        "brand_intelligence"
    ][
        "impersonation_detected"
    ]


def test_shared_public_email_not_officially_trusted():
    assert not is_known_official_domain(
        "gmail.com"
    )

    assert not is_known_official_domain(
        "outlook.com"
    )


def test_shared_cloud_host_not_officially_trusted():
    assert not is_known_official_domain(
        "amazonaws.com"
    )

    assert not is_known_official_domain(
        "myworkdayjobs.com"
    )
