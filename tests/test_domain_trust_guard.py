from __future__ import annotations

import pytest

from app.domain_intelligence.domain_trust_guard import (
    apply_domain_trust_guard,
    same_host_or_true_subdomain,
    sanitize_threatfox,
    verified_owner,
)


@pytest.mark.parametrize(
    ("candidate", "official"),
    [
        ("google.com", "google.com"),
        ("accounts.google.com", "google.com"),
        ("github.com", "github.com"),
        ("docs.python.org", "python.org"),
    ],
)
def test_exact_and_true_subdomains_match(
    candidate,
    official,
):
    assert same_host_or_true_subdomain(
        candidate,
        official,
    )


@pytest.mark.parametrize(
    ("candidate", "official"),
    [
        ("google-login.example", "google.com"),
        ("google.com.attacker.test", "google.com"),
        ("goog1e.com", "google.com"),
        ("github-auth.example", "github.com"),
        ("nvidia-secure.example", "nvidia.com"),
        ("micr0soft.com", "microsoft.com"),
    ],
)
def test_deceptive_domains_do_not_match(
    candidate,
    official,
):
    assert not same_host_or_true_subdomain(
        candidate,
        official,
    )


def test_verified_nvidia_owner_exists():
    owner = verified_owner(
        "https://nvidia.com/"
    )

    assert owner is not None
    assert owner["organization"] == "NVIDIA"


def test_unrelated_threatfox_result_is_filtered():
    payload = {
        "matched": True,
        "applied_score_adjustment": 30,
        "domain_lookup": {
            "ioc": "google-login.example"
        },
    }

    filtered = sanitize_threatfox(
        payload,
        "google.com",
    )

    assert not filtered["matched"]
    assert filtered["false_positive_filtered"]
    assert filtered["applied_score_adjustment"] == 0


def test_true_threatfox_subdomain_is_retained():
    payload = {
        "matched": True,
        "applied_score_adjustment": 30,
        "domain_lookup": {
            "ioc": "malware.accounts.google.com"
        },
    }

    filtered = sanitize_threatfox(
        payload,
        "google.com",
    )

    assert filtered["matched"]
    assert not filtered["false_positive_filtered"]


def test_guard_removes_false_85_floor():
    legacy = {
        "final_score": 85,
        "risk_score": 85,
        "risk_level": "critical",
        "classification": "likely_phishing",
        "is_phishing": True,
        "base_hybrid_score": 9,
        "total_intelligence_adjustment": 30,
        "global_brand_intelligence": {
            "official_domain_match": True,
            "impersonation_detected": False,
        },
        "threatfox_intelligence": {
            "matched": True,
            "applied_score_adjustment": 30,
            "domain_lookup": {
                "ioc": "google-login.example"
            },
        },
        "virustotal_intelligence": {
            "maximum_malicious": 0,
        },
        "reasons": [
            "ThreatFox malicious IOC match."
        ],
    }

    guarded = apply_domain_trust_guard(
        legacy,
        "https://google.com/",
    )

    assert guarded["final_score"] < 60
    assert not guarded["is_phishing"]
    assert guarded[
        "domain_trust_guard"
    ][
        "threatfox_false_positive_filtered"
    ]
