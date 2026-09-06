from __future__ import annotations

from app.global_entity_registry.reconciliation.domain_relationship import (
    classify_domain_relationship,
)


def test_exact_domains_agree():
    result = (
        classify_domain_relationship(
            "example.org",
            "www.example.org",
        )
    )

    assert (
        result.relationship
        == "exact_agreement"
    )


def test_same_registrable_domain():
    result = (
        classify_domain_relationship(
            "research.microsoft.com",
            "www.microsoft.com",
        )
    )

    assert (
        result.relationship
        in {
            "same_registrable_domain",
            "related_subdomain",
        }
    )


def test_different_domains_remain_different():
    result = (
        classify_domain_relationship(
            "nmu.edu.pk",
            "nmch.edu.pk",
        )
    )

    assert (
        result.relationship
        == "different_registrable_domains"
    )
