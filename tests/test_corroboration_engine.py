from app.detection.hybrid_detector import (
    analyze_url_hybrid,
)



def test_unknown_clean_url_cannot_be_high_from_ml_alone():
    result = analyze_url_hybrid(
        "https://small-university.so/admissions"
    )

    assert (
        result["final_score"]
        <= 34
    )

    assert (
        result["risk_level"]
        in {
            "low",
            "guarded",
            "medium",
        }
    )

    assert not result[
        "is_phishing"
    ]

    assert result[
        "corroborating_evidence"
    ][
        "strong_signal_count"
    ] == 0

    assert result[
        "corroborating_evidence"
    ][
        "final_score_cap_applied"
    ]

def test_unknown_clean_bank_url_is_not_automatically_phishing():
    result = analyze_url_hybrid(
        "https://community-bank.so/services"
    )

    assert result[
        "final_score"
    ] <= 34

    assert not result[
        "is_phishing"
    ]


def test_legitimate_unknown_office_url_is_neutral():
    result = analyze_url_hybrid(
        "https://small-office.ke/contact"
    )

    assert result[
        "corroborating_evidence"
    ][
        "maximum_score_without_more_evidence"
    ] == 34

    assert result[
        "final_score"
    ] <= 34


def test_brand_impersonation_and_verify_lure_remain_high():
    result = analyze_url_hybrid(
        "https://linkedln-login.example.com/verify"
    )

    evidence = result[
        "corroborating_evidence"
    ]

    assert (
        evidence[
            "strong_signal_count"
        ]
        >= 2
    )

    assert (
        result["final_score"]
        >= 70
    )

    assert result[
        "is_phishing"
    ]


def test_ip_and_password_lure_remain_high():
    result = analyze_url_hybrid(
        "http://203.0.113.50/password/verify"
    )

    evidence = result[
        "corroborating_evidence"
    ]

    assert (
        evidence[
            "strong_signal_count"
        ]
        >= 2
    )

    assert (
        result["final_score"]
        >= 70
    )


def test_one_weak_signal_cannot_be_high():
    result = analyze_url_hybrid(
        "http://small-company.example/about"
    )

    assert (
        result[
            "corroborating_evidence"
        ][
            "strong_signal_count"
        ]
        == 0
    )

    assert (
        result["final_score"]
        <= 39
    )
