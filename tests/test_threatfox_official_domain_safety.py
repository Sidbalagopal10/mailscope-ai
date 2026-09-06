from __future__ import annotations

import pytest

from app.domain_intelligence.safe_unified_profile import (
    OFFICIAL_DOMAIN_OVERRIDES,
)
from app.domain_intelligence.threatfox_relevance import (
    is_same_or_true_subdomain,
    sanitize_threatfox_payload,
)


@pytest.mark.parametrize(
    (
        "candidate",
        "requested",
    ),
    [
        (
            "google.com",
            "google.com",
        ),
        (
            "accounts.google.com",
            "google.com",
        ),
        (
            "github.com",
            "github.com",
        ),
        (
            "objects.githubusercontent.github.com",
            "github.com",
        ),
    ],
)
def test_exact_or_true_subdomain_matches(
    candidate,
    requested,
):
    assert is_same_or_true_subdomain(
        candidate,
        requested,
    )


@pytest.mark.parametrize(
    (
        "candidate",
        "requested",
    ),
    [
        (
            "google-login.example",
            "google.com",
        ),
        (
            "fakegoogle.com",
            "google.com",
        ),
        (
            "google.com.attacker.test",
            "google.com",
        ),
        (
            "m.s-google.com",
            "google.com",
        ),
        (
            "github-auth.example",
            "github.com",
        ),
        (
            "github.com.evil.test",
            "github.com",
        ),
        (
            "nvidia-secure.example",
            "nvidia.com",
        ),
        (
            "microsoft-login.example",
            "microsoft.com",
        ),
    ],
)
def test_deceptive_hosts_do_not_match(
    candidate,
    requested,
):
    assert not is_same_or_true_subdomain(
        candidate,
        requested,
    )


def test_irrelevant_threatfox_match_is_filtered():
    payload = {
        "matched": True,
        "applied_score_adjustment": 30,
        "domain_lookup": {
            "observation": {
                "ioc": (
                    "google-login.example"
                ),
            }
        },
    }

    result = sanitize_threatfox_payload(
        payload,
        "google.com",
    )

    assert not result[
        "matched"
    ]

    assert result[
        "false_positive_filtered"
    ]

    assert result[
        "applied_score_adjustment"
    ] == 0


def test_relevant_threatfox_match_is_retained():
    payload = {
        "matched": True,
        "applied_score_adjustment": 30,
        "domain_lookup": {
            "observation": {
                "ioc": (
                    "malware.accounts.google.com"
                ),
            }
        },
    }

    result = sanitize_threatfox_payload(
        payload,
        "google.com",
    )

    assert result[
        "matched"
    ]

    assert not result[
        "false_positive_filtered"
    ]


def test_nvidia_has_official_identity_override():
    assert (
        "nvidia.com"
        in OFFICIAL_DOMAIN_OVERRIDES
    )
