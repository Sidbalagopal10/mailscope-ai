from __future__ import annotations

from typing import Any

from app.global_entity_registry.database import connection
from app.global_entity_registry.gleif_resolution import (
    candidate_score,
    save_candidate,
)
from app.global_entity_registry.gleif_search_index import (
    search_names,
)


def registry_entity(
    entity_id: int,
) -> dict[str, Any] | None:
    with connection() as db:
        entity = db.execute(
            """
            SELECT *
            FROM entities
            WHERE id = ?
            """,
            (
                entity_id,
            ),
        ).fetchone()

        if entity is None:
            return None

        aliases = db.execute(
            """
            SELECT alias
            FROM entity_aliases
            WHERE entity_id = ?
            ORDER BY id
            LIMIT 25
            """,
            (
                entity_id,
            ),
        ).fetchall()

    result = dict(entity)

    result["aliases"] = [
        row["alias"]
        for row in aliases
    ]

    return result


def resolve_entity(
    entity_id: int,
    *,
    result_limit: int = 20,
) -> list[dict[str, Any]]:
    entity = registry_entity(
        entity_id
    )

    if entity is None:
        return []

    search_terms = [
        entity[
            "canonical_name"
        ],
        *entity.get(
            "aliases",
            [],
        )[:10],
    ]

    candidates: dict[
        str,
        dict[str, Any],
    ] = {}

    for term in search_terms:
        for result in search_names(
            term,
            limit=result_limit,
        ):
            lei = str(
                result[
                    "lei"
                ]
            )

            gleif_country = (
                result.get(
                    "legal_address_country"
                )
                or result.get(
                    "headquarters_country"
                )
            )

            assessment = candidate_score(
                registry_name=(
                    entity[
                        "canonical_name"
                    ]
                ),
                legal_name=(
                    result[
                        "name"
                    ]
                ),
                registry_country=(
                    entity.get(
                        "country_code"
                    )
                ),
                gleif_country=(
                    gleif_country
                ),
            )

            candidate = {
                "registry_entity_id": (
                    entity_id
                ),
                "registry_name": (
                    entity[
                        "canonical_name"
                    ]
                ),
                "registry_country": (
                    entity.get(
                        "country_code"
                    )
                ),
                "lei": lei,
                "gleif_name": (
                    result[
                        "name"
                    ]
                ),
                "gleif_country": (
                    gleif_country
                ),
                "gleif_status": (
                    result.get(
                        "entity_status"
                    )
                ),
                **assessment,
            }

            existing = candidates.get(
                lei
            )

            if (
                existing is None
                or candidate[
                    "confidence"
                ]
                > existing[
                    "confidence"
                ]
            ):
                candidates[
                    lei
                ] = candidate

    ordered = sorted(
        candidates.values(),
        key=lambda item: (
            item[
                "confidence"
            ],
            item[
                "name_similarity"
            ],
        ),
        reverse=True,
    )

    for candidate in ordered[
        :result_limit
    ]:
        save_candidate(
            registry_entity_id=(
                entity_id
            ),
            lei=candidate[
                "lei"
            ],
            assessment=candidate,
        )

    return ordered[
        :result_limit
    ]


def resolve_registry_sample(
    *,
    limit: int = 100,
) -> dict[str, Any]:
    with connection() as db:
        rows = db.execute(
            """
            SELECT id
            FROM entities
            ORDER BY id
            LIMIT ?
            """,
            (
                int(limit),
            ),
        ).fetchall()

    processed = 0
    high_confidence = 0
    candidate_count = 0

    for row in rows:
        results = resolve_entity(
            int(
                row[
                    "id"
                ]
            )
        )

        processed += 1

        for result in results:
            candidate_count += 1

            if (
                result[
                    "decision"
                ]
                == "high_confidence_candidate"
            ):
                high_confidence += 1

    return {
        "entities_processed": (
            processed
        ),
        "candidate_matches": (
            candidate_count
        ),
        "high_confidence_candidates": (
            high_confidence
        ),
    }
