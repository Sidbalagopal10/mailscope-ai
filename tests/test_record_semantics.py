from __future__ import annotations

from app.global_entity_registry.ingestion.relationship_builder import (
    build_website_relationship,
)
from app.global_entity_registry.ingestion.record_semantics import (
    evidence_for_identity_domain,
    identity_domains_for_record,
)
from app.global_entity_registry.models import (
    EntityRecord,
    SourceEvidence,
)


def test_structured_relationships_override_legacy_domains():
    record = EntityRecord(
        canonical_name="Example",
        domains=[
            "legacy-example.com",
        ],
        website_relationships=[
            build_website_relationship(
                "https://example.org/",
                source_name="test",
            ),
            build_website_relationship(
                "https://github.com/example",
                source_name="test",
            ),
        ],
    )

    assert (
        identity_domains_for_record(
            record
        )
        == [
            "example.org",
        ]
    )


def test_legacy_record_still_supported():
    record = EntityRecord(
        canonical_name="Legacy",
        domains=[
            "www.example.org",
        ],
    )

    assert (
        identity_domains_for_record(
            record
        )
        == [
            "example.org",
        ]
    )


def test_context_platform_never_identity():
    record = EntityRecord(
        canonical_name="Example",
        website_relationships=[
            build_website_relationship(
                "https://example.pages.dev/",
                source_name="test",
            )
        ],
    )

    assert (
        identity_domains_for_record(
            record
        )
        == []
    )


def test_www_evidence_follows_canonical_domain():
    evidence = SourceEvidence(
        source_name="test",
        evidence_type="official_website",
        confidence=0.90,
        raw_reference=(
            "https://www.example.org/"
        ),
    )

    record = EntityRecord(
        canonical_name="Example",
        evidence={
            "www.example.org": [
                evidence,
            ]
        },
    )

    result = evidence_for_identity_domain(
        record,
        "example.org",
    )

    assert (
        result
        == [
            evidence,
        ]
    )


def test_duplicate_equivalent_evidence_deduplicates():
    evidence = SourceEvidence(
        source_name="test",
        source_record_id="123",
        evidence_type="official_website",
        confidence=0.90,
        raw_reference="https://example.org/",
    )

    record = EntityRecord(
        canonical_name="Example",
        evidence={
            "example.org": [
                evidence,
            ],
            "www.example.org": [
                evidence,
            ],
        },
    )

    result = evidence_for_identity_domain(
        record,
        "example.org",
    )

    assert len(
        result
    ) == 1
