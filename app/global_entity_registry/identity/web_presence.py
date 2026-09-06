from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from app.global_entity_registry.database import (
    connection,
)
from app.global_entity_registry.domain_utils import (
    canonical_identity_domain,
)


class WebPresenceMode(
    str,
    Enum,
):
    EXCLUSIVE = "exclusive"
    SHARED = "shared"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class WebPresenceAssessment:
    domain: str
    mode: WebPresenceMode

    entity_count: int

    entities: tuple[
        str,
        ...
    ]

    reason: str

    should_penalize_identity: bool


def _domain_entities(
    domain: str,
) -> list[
    dict[str, Any]
]:
    canonical = canonical_identity_domain(
        domain
    )

    if not canonical:
        return []

    with connection() as db:
        rows = db.execute(
            """
            SELECT DISTINCT
                e.id,
                e.canonical_name,
                e.entity_type,
                e.country_code

            FROM domains d

            JOIN entities e
              ON e.id = d.entity_id

            WHERE d.domain = ?

            ORDER BY e.canonical_name
            """,
            (
                canonical,
            ),
        ).fetchall()

    return [
        dict(
            row
        )
        for row in rows
    ]


def _relationship_urls(
    domain: str,
) -> list[
    dict[str, Any]
]:
    canonical = canonical_identity_domain(
        domain
    )

    if not canonical:
        return []

    with connection() as db:
        try:
            rows = db.execute(
                """
                SELECT DISTINCT
                    w.entity_id,
                    w.original_value,
                    w.hostname,
                    w.relationship_type,
                    w.source_name

                FROM entity_website_relationships w

                WHERE w.hostname = ?
                   OR w.hostname = ?

                ORDER BY
                    w.entity_id,
                    w.original_value
                """,
                (
                    canonical,
                    "www." + canonical,
                ),
            ).fetchall()

        except Exception:
            return []

    return [
        dict(
            row
        )
        for row in rows
    ]


def assess_web_presence(
    domain: str,
) -> WebPresenceAssessment:
    canonical = canonical_identity_domain(
        domain
    )

    if not canonical:
        return WebPresenceAssessment(
            domain="",
            mode=(
                WebPresenceMode.UNKNOWN
            ),
            entity_count=0,
            entities=(),
            reason="Invalid domain.",
            should_penalize_identity=False,
        )

    entities = _domain_entities(
        canonical
    )

    if not entities:
        return WebPresenceAssessment(
            domain=canonical,
            mode=(
                WebPresenceMode.UNKNOWN
            ),
            entity_count=0,
            entities=(),
            reason=(
                "No organization-domain relationships "
                "exist for this hostname."
            ),
            should_penalize_identity=False,
        )

    names = tuple(
        str(
            row[
                "canonical_name"
            ]
        )
        for row in entities
    )

    if len(
        entities
    ) == 1:
        return WebPresenceAssessment(
            domain=canonical,
            mode=(
                WebPresenceMode.EXCLUSIVE
            ),
            entity_count=1,
            entities=names,
            reason=(
                "Only one organization currently uses "
                "this canonical hostname in the registry."
            ),
            should_penalize_identity=False,
        )

    relationships = (
        _relationship_urls(
            canonical
        )
    )

    # Important:
    #
    # Multiple organizations using the same hostname is
    # not automatically conflicting ownership.
    #
    # Government portals, health systems, university
    # systems and umbrella organizations often host many
    # legitimate organizational web presences.
    #
    # If multiple distinct original URLs exist, that is
    # positive evidence for a shared hosting/web-presence
    # relationship rather than exclusive ownership.
    unique_original_urls = {
        str(
            row.get(
                "original_value"
            )
            or ""
        )
        for row in relationships
        if row.get(
            "original_value"
        )
    }

    relationship_entities = {
        int(
            row[
                "entity_id"
            ]
        )
        for row in relationships
        if row.get(
            "entity_id"
        )
        is not None
    }

    if (
        len(
            relationship_entities
        ) >= 2
        or len(
            unique_original_urls
        ) >= 2
    ):
        return WebPresenceAssessment(
            domain=canonical,
            mode=(
                WebPresenceMode.SHARED
            ),
            entity_count=len(
                entities
            ),
            entities=names,
            reason=(
                "Multiple organizations legitimately "
                "use this hostname as a shared web "
                "presence. Shared presence is not "
                "exclusive domain ownership."
            ),
            should_penalize_identity=False,
        )

    # Even without sufficient path-level relationship
    # evidence, multiple entities alone are not enough
    # to conclude malicious or contradictory ownership.
    #
    # Preserve ambiguity for later graph reasoning.
    return WebPresenceAssessment(
        domain=canonical,
        mode=(
            WebPresenceMode.AMBIGUOUS
        ),
        entity_count=len(
            entities
        ),
        entities=names,
        reason=(
            "Multiple organizations are associated with "
            "the hostname, but current evidence cannot "
            "yet distinguish shared web presence from "
            "true ownership ambiguity."
        ),
        should_penalize_identity=False,
    )
