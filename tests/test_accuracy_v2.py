from app.detection.brand_intelligence import (
    inspect_brand_impersonation,
)
from app.detection.email_content_analyzer import (
    analyze_email_content,
)
from app.detection.hybrid_detector import (
    calculate_heuristic_score,
)


def test_google_typo_detected():
    result = inspect_brand_impersonation(
        "https://g00gle.example.com/login"
    )

    assert result[
        "impersonation_detected"
    ]


def test_apple_typo_detected():
    result = inspect_brand_impersonation(
        "https://appple.example.net/account"
    )

    assert result[
        "impersonation_detected"
    ]


def test_official_google_not_impersonation():
    result = inspect_brand_impersonation(
        "https://accounts.google.com/"
    )

    assert not result[
        "impersonation_detected"
    ]


def test_tracking_url_not_critical_from_length():
    score, _ = calculate_heuristic_score(
        "https://click.email.linkedin.com/"
        "?qs="
        + "a" * 400
    )

    assert score < 35


def test_normal_bank_language_not_phishing():
    result = analyze_email_content(
        subject=(
            "Your monthly bank statement "
            "is available"
        ),
        body=(
            "Your statement is ready. "
            "Review recent transactions "
            "in your mobile banking app."
        ),
        sender=(
            "alerts@bank.example"
        ),
    )

    assert result[
        "content_score"
    ] < 20


def test_normal_job_application_not_phishing():
    result = analyze_email_content(
        subject=(
            "Application received"
        ),
        body=(
            "Thank you for applying. "
            "A recruiter will review your "
            "application and contact you."
        ),
        sender=(
            "jobs@company.example"
        ),
    )

    assert result[
        "content_score"
    ] < 20


def test_job_check_scam_high_risk():
    result = analyze_email_content(
        subject=(
            "Remote job offer"
        ),
        body=(
            "Your Telegram interview is complete. "
            "We will send you a check to purchase "
            "equipment. Deposit the check immediately."
        ),
        sender=(
            "recruiter@example.com"
        ),
    )

    assert result[
        "content_score"
    ] >= 40
