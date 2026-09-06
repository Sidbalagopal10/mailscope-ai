from __future__ import annotations

from app.global_entity_registry.domain_utils import (
    canonical_identity_domain,
)


def test_www_collapses():
    assert (
        canonical_identity_domain(
            "https://www.example.edu/"
        )
        == "example.edu"
    )


def test_plain_domain_unchanged():
    assert (
        canonical_identity_domain(
            "example.edu"
        )
        == "example.edu"
    )


def test_meaningful_subdomain_preserved():
    assert (
        canonical_identity_domain(
            "https://research.microsoft.com/"
        )
        == "research.microsoft.com"
    )


def test_accounts_subdomain_preserved():
    assert (
        canonical_identity_domain(
            "https://accounts.google.com/"
        )
        == "accounts.google.com"
    )


def test_empty_value():
    assert (
        canonical_identity_domain(
            ""
        )
        == ""
    )
