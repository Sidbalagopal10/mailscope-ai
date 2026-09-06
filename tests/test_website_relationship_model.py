from __future__ import annotations

from app.global_entity_registry.ingestion.relationship_builder import (
    build_website_relationship,
)
from app.global_entity_registry.models import (
    EntityRecord,
    WebsiteRelationship,
)


def test_entity_record_remains_backward_compatible():
    record = EntityRecord(
        canonical_name="Example Organization",
        domains=[
            "example.org",
        ],
    )

    assert (
        record.domains
        == [
            "example.org",
        ]
    )

    assert (
        record.website_relationships
        == []
    )


def test_official_candidate_relationship():
    result = build_website_relationship(
        "https://microsoft.com/",
        source_name="test",
        confidence=0.90,
    )

    assert isinstance(
        result,
        WebsiteRelationship,
    )

    assert (
        result.hostname
        == "microsoft.com"
    )

    assert (
        result.relationship_type
        == "official_website_candidate"
    )

    assert (
        result.eligible_for_domain_identity
        is True
    )


def test_github_relationship_not_domain_identity():
    result = build_website_relationship(
        "https://github.com/example/project",
        source_name="test",
    )

    assert (
        result.relationship_type
        == "code_repository"
    )

    assert (
        result.eligible_for_domain_identity
        is False
    )

    assert (
        result.preserve_as_relationship
        is True
    )


def test_shared_host_relationship():
    result = build_website_relationship(
        "https://example.pages.dev/"
    )

    assert (
        result.relationship_type
        == "user_generated_hosting"
    )

    assert (
        result.provider
        == "Cloudflare"
    )


def test_source_metadata_preserved():
    result = build_website_relationship(
        "https://example.org/",
        source_name="ror",
        source_record_id="https://ror.org/example",
        confidence=0.97,
    )

    assert (
        result.source_name
        == "ror"
    )

    assert (
        result.source_record_id
        == "https://ror.org/example"
    )

    assert (
        result.confidence
        == 0.97
    )
