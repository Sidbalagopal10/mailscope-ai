from __future__ import annotations

import pytest

from app.domain_intelligence.safe_unified_profile import (
    analyze_safe_unified_domain_profile,
)


OFFICIAL_DOMAINS = [
    "google.com",
    "microsoft.com",
    "apple.com",
    "nvidia.com",
    "github.com",
    "gwu.edu",
]


@pytest.mark.parametrize(
    "domain",
    OFFICIAL_DOMAINS,
)
def test_official_domain_not_impersonation(
    domain,
):
    result = (
        analyze_safe_unified_domain_profile(
            f"https://{domain}/",
            force_refresh=False,
            include_ct_subdomains=False,
        )
    )

    brand = result.get(
        "global_brand_intelligence",
        {},
    )

    assert brand.get(
        "official_domain_match"
    ) is True

    assert not brand.get(
        "impersonation_detected",
        False,
    )


@pytest.mark.parametrize(
    "domain",
    OFFICIAL_DOMAINS,
)
def test_official_domain_not_high_or_critical_without_relevant_ioc(
    domain,
):
    result = (
        analyze_safe_unified_domain_profile(
            f"https://{domain}/",
            force_refresh=False,
            include_ct_subdomains=False,
        )
    )

    guard = result.get(
        "domain_safety_guard",
        {},
    )

    if guard.get(
        "threatfox_false_positive_filtered"
    ):
        assert result[
            "final_score"
        ] < 60

        assert result[
            "risk_level"
        ] in {
            "low",
            "moderate",
        }

        assert not result[
            "is_phishing"
        ]
