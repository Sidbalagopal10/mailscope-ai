from __future__ import annotations

from app.global_entity_registry.models import (
    EntityRecord,
    SourceEvidence,
)
from app.global_entity_registry.repository import (
    upsert_entity,
)


SEED_RECORDS = [
    EntityRecord(
        canonical_name="Google",
        entity_type="company",
        country_code="US",
        country_name="United States",
        continent="North America",
        domains=[
            "google.com"
        ],
        evidence={
            "google.com": [
                SourceEvidence(
                    source_name="seed_validation",
                    evidence_type="official_domain",
                    confidence=1.0,
                    authoritative=False,
                )
            ]
        },
    ),
    EntityRecord(
        canonical_name="The George Washington University",
        entity_type="education",
        country_code="US",
        country_name="United States",
        continent="North America",
        domains=[
            "gwu.edu"
        ],
        evidence={
            "gwu.edu": [
                SourceEvidence(
                    source_name="seed_validation",
                    evidence_type="official_domain",
                    confidence=1.0,
                    authoritative=False,
                )
            ]
        },
    ),
    EntityRecord(
        canonical_name="Indian Space Research Organisation",
        entity_type="government",
        country_code="IN",
        country_name="India",
        continent="Asia",
        domains=[
            "isro.gov.in"
        ],
        evidence={
            "isro.gov.in": [
                SourceEvidence(
                    source_name="seed_validation",
                    evidence_type="official_domain",
                    confidence=1.0,
                    authoritative=False,
                )
            ]
        },
    ),
]


def seed_registry() -> None:
    for record in SEED_RECORDS:
        upsert_entity(
            record
        )


if __name__ == "__main__":
    seed_registry()

    print(
        "Seed registry created."
    )
