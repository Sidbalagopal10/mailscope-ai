from __future__ import annotations

from app.organization_graph.dynamic_brand_engine import (
    analyze_brand_identity,
)
from app.organization_graph.resolver import (
    candidate_similarity,
)


def test_alias_similarity_uses_matched_alias():
    match = {
        "canonical_name": (
            "Microsoft (United States)"
        ),
        "matched_name": (
            "Microsoft Corporation"
        ),
        "core_name": "microsoft",
    }

    result = candidate_similarity(
        "microsoft",
        match,
    )

    assert result >= 0.95


def test_verified_microsoft_subdomain_not_impersonation():
    result = analyze_brand_identity(
        "https://research.microsoft.com/"
    )

    assert (
        result[
            "possible_impersonation"
        ]
        is False
    )

    assert (
        result[
            "official_matches"
        ]
    )


def test_microsoft_shared_host_becomes_candidate():
    result = analyze_brand_identity(
        "https://microsoft-login.pages.dev/account/login"
    )

    assert (
        result[
            "possible_impersonation"
        ]
        is True
    )

    assert (
        result[
            "impersonation_candidates"
        ]
    )


def test_generic_research_token_not_brand():
    result = analyze_brand_identity(
        "https://research-portal.example/"
    )

    tokens = set(
        result[
            "tokens"
        ]
    )

    assert (
        "research"
        not in tokens
    )


def test_unknown_company_stays_unknown():
    result = analyze_brand_identity(
        "https://unknown-company.example/"
    )

    assert (
        result[
            "possible_impersonation"
        ]
        is False
    )
