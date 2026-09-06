from __future__ import annotations

import json
from typing import Any

from app.global_entity_registry.database import (
    connection,
)
from app.global_entity_registry.gleif_database import (
    initialize_gleif_schema,
)
from app.global_entity_registry.gleif_repository import (
    name_similarity,
    utc_now,
)


def candidate_score(
    *,
    registry_name: str,
    legal_name: str,
    registry_country: str | None,
    gleif_country: str | None,
) -> dict[str, Any]:
    similarity = name_similarity(
        registry_name,
        legal_name,
    )

    country_agreement = bool(
        registry_country
        and gleif_country
        and registry_country.upper()
        == gleif_country.upper()
    )

    score = similarity * 0.85

    if country_agreement:
        score += 0.15

    score = min(
        score,
        1.0,
    )

    if (
        similarity >= 0.97
        and country_agreement
    ):
        decision = (
            "high_confidence_candidate"
        )

    elif score >= 0.80:
        decision = "candidate"

    else:
        decision = (
            "insufficient_evidence"
        )

    return {
        "name_similarity": (
            similarity
        ),
        "country_agreement": (
            country_agreement
        ),
        "confidence": round(
            score,
            4,
        ),
        "decision": decision,
    }


def save_candidate(
    *,
    registry_entity_id: int,
    lei: str,
    assessment: dict[str, Any],
) -> None:
    initialize_gleif_schema()

    with connection() as db:
        db.execute(
            """
            INSERT INTO entity_resolution_candidates (
                registry_entity_id,
                lei,
                name_similarity,
                country_agreement,
                external_id_agreement,
                confidence,
                decision,
                evidence,
                created_at
            )
            VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)

            ON CONFLICT(
                registry_entity_id,
                lei
            )
            DO UPDATE SET
                name_similarity =
                    excluded.name_similarity,
                country_agreement =
                    excluded.country_agreement,
                confidence =
                    excluded.confidence,
                decision =
                    excluded.decision,
                evidence =
                    excluded.evidence,
                created_at =
                    excluded.created_at
            """,
            (
                registry_entity_id,
                lei,
                assessment[
                    "name_similarity"
                ],
                int(
                    assessment[
                        "country_agreement"
                    ]
                ),
                assessment[
                    "confidence"
                ],
                assessment[
                    "decision"
                ],
                json.dumps(
                    assessment,
                    sort_keys=True,
                ),
                utc_now(),
            ),
        )

        db.commit()
