from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.global_entity_registry.database import (
    connection,
)
from app.global_entity_registry.domain_utils import (
    canonical_identity_domain,
)
from app.global_entity_registry.identity.evidence_state import (
    IdentityEvidenceAssessment,
    IdentityEvidenceState,
)
from app.global_entity_registry.reconciliation.domain_relationship import (
    classify_domain_relationship,
)


def domain_evidence(
    domain: str,
) -> dict[str, Any]:
    wanted = canonical_identity_domain(
        domain
    )

    if not wanted:
        return {
            "domain": "",
            "matches": [],
        }

    with connection() as db:
        rows = db.execute(
            """
            SELECT
                e.id AS entity_id,
                e.canonical_name,

                d.id AS domain_id,
                d.domain,

                es.source_name,
                es.evidence_type,
                es.confidence,
                es.authoritative

            FROM domains d

            JOIN entities e
              ON e.id = d.entity_id

            LEFT JOIN evidence_sources es
              ON es.domain_id = d.id

            WHERE d.domain = ?

            ORDER BY
                e.canonical_name,
                es.source_name
            """,
            (
                wanted,
            ),
        ).fetchall()

    return {
        "domain": wanted,
        "matches": [
            dict(
                row
            )
            for row in rows
        ],
    }


def _entity_domain_sources(
    entity_id: int,
) -> dict[
    str,
    set[str],
]:
    with connection() as db:
        rows = db.execute(
            """
            SELECT
                d.domain,
                es.source_name

            FROM domains d

            LEFT JOIN evidence_sources es
              ON es.domain_id = d.id

            WHERE d.entity_id = ?
            """,
            (
                int(
                    entity_id
                ),
            ),
        ).fetchall()

    result: dict[
        str,
        set[str],
    ] = defaultdict(
        set
    )

    for row in rows:
        domain = canonical_identity_domain(
            str(
                row[
                    "domain"
                ]
                or ""
            )
        )

        source = str(
            row[
                "source_name"
            ]
            or ""
        ).strip()

        if not domain:
            continue

        if source:
            result[
                domain
            ].add(
                source
            )

        else:
            result.setdefault(
                domain,
                set(),
            )

    return dict(
        result
    )


def _source_conflicts(
    *,
    target_domain: str,
    entity_id: int,
) -> list[str]:
    domains = _entity_domain_sources(
        entity_id
    )

    target_sources = domains.get(
        target_domain,
        set(),
    )

    if not target_sources:
        return []

    conflicts = []

    for other_domain, other_sources in (
        domains.items()
    ):
        if other_domain == target_domain:
            continue

        if not other_sources:
            continue

        # Different source claims another registrable
        # domain for the same linked organization.
        if target_sources.isdisjoint(
            other_sources
        ):
            relationship = (
                classify_domain_relationship(
                    target_domain,
                    other_domain,
                )
            )

            if (
                relationship.relationship
                == "different_registrable_domains"
            ):
                conflicts.append(
                    other_domain
                )

    return sorted(
        set(
            conflicts
        )
    )


def assess_domain_identity(
    domain: str,
) -> list[
    IdentityEvidenceAssessment
]:
    evidence = domain_evidence(
        domain
    )

    canonical_domain = evidence[
        "domain"
    ]

    rows = evidence[
        "matches"
    ]

    if not canonical_domain:
        return [
            IdentityEvidenceAssessment(
                entity_id=None,
                canonical_name=None,
                domain="",
                state=(
                    IdentityEvidenceState.UNKNOWN
                ),
                source_count=0,
                sources=(),
                confidence=0.0,
                reasons=(
                    "Invalid or empty domain.",
                ),
            )
        ]

    if not rows:
        return [
            IdentityEvidenceAssessment(
                entity_id=None,
                canonical_name=None,
                domain=canonical_domain,
                state=(
                    IdentityEvidenceState.UNKNOWN
                ),
                source_count=0,
                sources=(),
                confidence=0.0,
                reasons=(
                    "No organization identity record "
                    "exists for this domain.",
                ),
            )
        ]

    grouped: dict[
        int,
        list[dict[str, Any]],
    ] = defaultdict(
        list
    )

    for row in rows:
        grouped[
            int(
                row[
                    "entity_id"
                ]
            )
        ].append(
            row
        )

    assessments = []

    for entity_id, entity_rows in (
        grouped.items()
    ):
        first = entity_rows[
            0
        ]

        sources = sorted(
            {
                str(
                    row[
                        "source_name"
                    ]
                )
                for row in entity_rows
                if row[
                    "source_name"
                ]
            }
        )

        source_count = len(
            sources
        )

        conflicts = _source_conflicts(
            target_domain=canonical_domain,
            entity_id=entity_id,
        )

        reasons = []

        if source_count >= 2:
            state = (
                IdentityEvidenceState.VERIFIED
            )

            confidence = 0.97

            reasons.append(
                "Two or more independent sources "
                "support this canonical domain."
            )

        elif (
            source_count == 1
            and conflicts
        ):
            state = (
                IdentityEvidenceState.CONFLICTING
            )

            confidence = 0.55

            reasons.append(
                "The domain has source support, but "
                "another independent source linked to "
                "the same organization asserts a "
                "different registrable domain."
            )

        elif source_count == 1:
            state = (
                IdentityEvidenceState.SUPPORTED
            )

            confidence = 0.78

            reasons.append(
                "One source currently supports this "
                "organization-domain relationship."
            )

        else:
            state = (
                IdentityEvidenceState.UNKNOWN
            )

            confidence = 0.20

            reasons.append(
                "The domain exists in the registry but "
                "has no usable evidence source."
            )

        if conflicts:
            reasons.append(
                "Conflicting candidate domains: "
                + ", ".join(
                    conflicts
                )
            )

        assessments.append(
            IdentityEvidenceAssessment(
                entity_id=entity_id,

                canonical_name=str(
                    first[
                        "canonical_name"
                    ]
                ),

                domain=canonical_domain,

                state=state,

                source_count=(
                    source_count
                ),

                sources=tuple(
                    sources
                ),

                confidence=(
                    confidence
                ),

                reasons=tuple(
                    reasons
                ),

                conflicting_domains=tuple(
                    conflicts
                ),

                metadata={
                    "evidence_rows": len(
                        entity_rows
                    ),
                },
            )
        )

    assessments.sort(
        key=lambda item: (
            item.state
            == IdentityEvidenceState.VERIFIED,
            item.source_count,
            item.confidence,
        ),
        reverse=True,
    )

    return assessments
