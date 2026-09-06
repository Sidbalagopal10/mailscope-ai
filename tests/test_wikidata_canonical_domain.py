from __future__ import annotations

from app.global_entity_registry.domain_utils import (
    canonical_identity_domain,
)


def test_wikidata_www_matches_ror_root():
    assert (
        canonical_identity_domain(
            "www.jpmc.com.pk"
        )
        == "jpmc.com.pk"
    )


def test_ucsf_www_matches_root():
    assert (
        canonical_identity_domain(
            "www.ucsfbenioffchildrens.org"
        )
        == "ucsfbenioffchildrens.org"
    )


def test_meaningful_wikidata_subdomain_survives():
    assert (
        canonical_identity_domain(
            "research.microsoft.com"
        )
        == "research.microsoft.com"
    )
