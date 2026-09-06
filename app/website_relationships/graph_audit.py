from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.global_entity_registry.database import (
    connection,
)
from app.website_relationships.classifier import (
    classify_website_relationship,
)


REPORT = Path(
    "data/website_relationships/"
    "latest_platform_contamination_report.json"
)


def audit_graph_domains() -> dict[str, Any]:
    with connection() as db:
        rows = db.execute(
            """
            SELECT
                d.id AS graph_domain_id,
                d.node_id,
                d.domain,
                d.relationship_type,
                d.source_count,
                d.integrity_state,
                d.usable_for_identity,

                n.canonical_name,
                n.entity_type,
                n.country_code

            FROM organization_graph_domains d

            JOIN organization_graph_nodes n
              ON n.id = d.node_id

            ORDER BY d.domain
            """
        ).fetchall()

    contaminated = []

    by_type: dict[str, int] = {}

    for row in rows:
        result = classify_website_relationship(
            str(
                row[
                    "domain"
                ]
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

        relationship_type = str(
            result[
                "relationship_type"
            ]
        )

        by_type[
            relationship_type
        ] = (
            by_type.get(
                relationship_type,
                0,
            )
            + 1
        )

    report = {
        "graph_domains_examined": len(rows),
        "platform_contaminated_claims": len(
            contaminated
        ),
        "by_relationship_type": by_type,
        "claims": contaminated,
    }

    REPORT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
            default=str,
        ),
        encoding="utf-8",
    )

    return report
