from __future__ import annotations

from collections import Counter
from typing import Any

from app.global_entity_registry.database import (
    connection,
)
from app.website_relationships.classifier import (
    classify_website_relationship,
)


def diagnostic() -> dict[str, Any]:
    with connection() as db:
        rows = db.execute(
            """
            SELECT
                d.id AS domain_id,
                d.entity_id,
                d.domain,

                e.canonical_name,

                es.source_name,
                es.evidence_type,
                es.source_record_id

            FROM domains d

            JOIN entities e
              ON e.id = d.entity_id

            LEFT JOIN evidence_sources es
              ON es.domain_id = d.id

            WHERE d.active = 1
            """
        ).fetchall()

    contaminated = []

    source_counts = Counter()

    for row in rows:
        result = (
            classify_website_relationship(
                str(
                    row[
                        "domain"
                    ]
                )
            )
        )

        if result[
            "eligible_as_official_domain"
        ]:
            continue

        item = {
            **dict(row),
            "classification": result,
        }

        contaminated.append(
            item
        )

        source_counts.update(
            [
                str(
                    row[
                        "source_name"
                    ]
                    or "unknown"
                )
            ]
        )

    return {
        "contaminated_source_rows": len(
            contaminated
        ),
        "source_counts": (
            source_counts.most_common()
        ),
        "examples": contaminated[
            :200
        ],
    }
