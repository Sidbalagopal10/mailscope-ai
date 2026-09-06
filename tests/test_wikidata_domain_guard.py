from __future__ import annotations

from app.global_entity_registry.ingestion.website_policy import (
    evaluate_website_for_ingestion,
)


def test_github_rejected_before_wikidata_domain_write():
    decision = evaluate_website_for_ingestion(
        "https://github.com/example"
    )

    assert (
        decision.eligible_for_domain_identity
        is False
    )


def test_vercel_rejected_before_wikidata_domain_write():
    decision = evaluate_website_for_ingestion(
        "https://example.vercel.app/"
    )

    assert (
        decision.eligible_for_domain_identity
        is False
    )


def test_normal_domain_allowed_before_wikidata_write():
    decision = evaluate_website_for_ingestion(
        "https://example.org/"
    )

    assert (
        decision.eligible_for_domain_identity
        is True
    )
