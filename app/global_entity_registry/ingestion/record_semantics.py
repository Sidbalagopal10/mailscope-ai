from __future__ import annotations

from app.global_entity_registry.domain_utils import (
    canonical_identity_domain,
)
from app.global_entity_registry.models import (
    EntityRecord,
    SourceEvidence,
)


def identity_domains_for_record(
    record: EntityRecord,
) -> list[str]:
    """
    Return domains allowed to establish organization identity.

    NEW records:
        WebsiteRelationship is authoritative.

    LEGACY records:
        domains[] remains supported temporarily.
    """

    relationships = list(
        getattr(
            record,
            "website_relationships",
            [],
        )
        or []
    )

    values: list[str] = []

    if relationships:
        for relationship in relationships:
            if not (
                relationship.hostname
                and relationship.eligible_for_domain_identity
            ):
                continue

            domain = canonical_identity_domain(
                relationship.hostname
            )

            if domain:
                values.append(
                    domain
                )

    else:
        # Backward compatibility for old seed/import code.
        for raw_domain in (
            record.domains
            or []
        ):
            domain = canonical_identity_domain(
                raw_domain
            )

            if domain:
                values.append(
                    domain
                )

    return list(
        dict.fromkeys(
            values
        )
    )


def evidence_for_identity_domain(
    record: EntityRecord,
    domain: str,
) -> list[SourceEvidence]:
    """
    Merge evidence whose source hostname canonicalizes to
    the same identity domain.

    Example:

        example.edu
        www.example.edu

    can both support:

        example.edu
    """

    wanted = canonical_identity_domain(
        domain
    )

    if not wanted:
        return []

    results: list[SourceEvidence] = []

    seen = set()

    for raw_domain, evidence_items in (
        record.evidence
        or {}
    ).items():
        normalized = canonical_identity_domain(
            raw_domain
        )

        if normalized != wanted:
            continue

        for item in evidence_items:
            key = (
                item.source_name,
                item.source_record_id,
                item.evidence_type,
                item.raw_reference,
            )

            if key in seen:
                continue

            seen.add(
                key
            )

            results.append(
                item
            )

    return results
