from __future__ import annotations

from app.benchmarking.hosting_detector import (
    analyze_with_hosting,
)
from app.benchmarking.offline_detector import (
    analyze_offline,
)


def test_normal_domain_not_inflated_by_hosting():
    baseline = analyze_offline(
        "https://example.com/"
    )

    hosting = analyze_with_hosting(
        "https://example.com/"
    )

    assert (
        hosting[
            "risk_score"
        ]
        == baseline[
            "risk_score"
        ]
    )


def test_shared_host_alone_does_not_raise_risk():
    result = analyze_with_hosting(
        "https://my-cooking-blog.pages.dev/recipes"
    )

    malicious_hosting_contributions = [
        item
        for item in result[
            "contributions"
        ]
        if (
            item[
                "source"
            ]
            == "hosting_intelligence"
            and item[
                "direction"
            ]
            == "malicious"
        )
    ]

    assert (
        malicious_hosting_contributions
        == []
    )


def test_brand_login_shared_host_has_corroboration():
    result = analyze_with_hosting(
        "https://microsoft-login.pages.dev/account/login"
    )

    sources = {
        item[
            "source"
        ]
        for item in result[
            "contributions"
        ]
    }

    assert (
        "hosting_corroboration"
        in sources
    )


def test_hosting_result_contains_platform_context():
    result = analyze_with_hosting(
        "https://example.vercel.app/"
    )

    assert (
        result[
            "hosting"
        ][
            "matched"
        ]
        is True
    )

    assert (
        result[
            "hosting"
        ][
            "provider"
        ]
        == "Vercel"
    )
