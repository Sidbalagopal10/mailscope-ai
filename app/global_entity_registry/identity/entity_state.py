from __future__ import annotations

from typing import Any

from app.global_entity_registry.database import (
    connection,
)
from app.global_entity_registry.identity.evaluator import (
    assess_domain_identity,
)


def entity_identity_state(
    entity_id: int,
) -> dict[str, Any]:
    with connection() as db:
        entity = db.execute(
            """
            SELECT
                id,
                canonical_name,
                entity_type,
                country_code

            FROM entities

            WHERE id = ?
            """,
            (
                int(
                    entity_id
                ),
            ),
        ).fetchone()

        if entity is None:
            return {
                "entity_id": entity_id,
                "found": False,
            }

        domains = db.execute(
            """
            SELECT domain
            FROM domains
            WHERE entity_id = ?
            ORDER BY domain
            """,
            (
                int(
                    entity_id
                ),
            ),
        ).fetchall()

    assessments = []

    for row in domains:
        domain = str(
            row[
                "domain"
            ]
        )

        results = (
            assess_domain_identity(
                domain
            )
        )

        for result in results:
            if (
                result.entity_id
                == entity_id
            ):
                assessments.append(
                    result
                )

    return {
        "entity_id": int(
            entity[
                "id"
            ]
        ),

        "found": True,

        "canonical_name": (
            entity[
                "canonical_name"
            ]
        ),

        "entity_type": (
            entity[
                "entity_type"
            ]
        ),

        "country_code": (
            entity[
                "country_code"
            ]
        ),

        "domains": [
            {
                "domain": item.domain,
                "state": item.state.value,
                "confidence": (
                    item.confidence
                ),
                "sources": list(
                    item.sources
                ),
                "conflicting_domains": (
                    list(
                        item.conflicting_domains
                    )
                ),
                "reasons": list(
                    item.reasons
                ),
            }
            for item in assessments
        ],
    }
