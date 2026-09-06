from __future__ import annotations

from app.global_entity_registry.ingestion.relationship_builder import (
    build_website_relationship,
)


def test_wikidata_regular_website_is_identity_candidate():
    result = build_website_relationship(
        "https://example.org/",
        source_name="wikidata_dump_p856",
        source_record_id="Q123",
        confidence=0.82,
    )

    assert (
        result.eligible_for_domain_identity
        is True
    )

    assert (
        result.relationship_type
        == "official_website_candidate"
    )


def test_wikidata_github_profile_is_not_identity():
    result = build_website_relationship(
        "https://github.com/example-org",
        source_name="wikidata_dump_p856",
        source_record_id="Q123",
        confidence=0.82,
    )

    assert (
        result.eligible_for_domain_identity
        is False
    )

    assert (
        result.relationship_type
        == "code_repository"
    )


def test_wikidata_linkedin_profile_is_not_identity():
    result = build_website_relationship(
        "https://linkedin.com/company/example",
        source_name="wikidata_dump_p856",
        source_record_id="Q123",
        confidence=0.82,
    )

    assert (
        result.eligible_for_domain_identity
        is False
    )


def test_wikidata_pages_dev_is_not_identity():
    result = build_website_relationship(
        "https://example.pages.dev/",
        source_name="wikidata_dump_p856",
        source_record_id="Q123",
        confidence=0.82,
    )

    assert (
        result.eligible_for_domain_identity
        is False
    )

    assert (
        result.provider
        == "Cloudflare"
    )


def test_wikidata_real_domain_remains_identity_candidate():
    result = build_website_relationship(
        "https://www.isro.gov.in/",
        source_name="wikidata_dump_p856",
        source_record_id="Q123",
        confidence=0.82,
    )

    assert (
        result.eligible_for_domain_identity
        is True
    )
