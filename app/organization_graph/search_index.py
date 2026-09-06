from __future__ import annotations

import re
from typing import Any

from app.global_entity_registry.database import (
    connection,
)
from app.organization_graph.database import (
    initialize_graph_schema,
)
from app.organization_graph.normalization import (
    normalize_organization_name,
    organization_core_name,
)


FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS organization_name_fts
USING fts5(
    name,
    normalized_name,
    core_name,
    node_id UNINDEXED,
    name_type UNINDEXED,
    source_name UNINDEXED,
    confidence UNINDEXED,
    tokenize='unicode61 remove_diacritics 2'
);
"""


def initialize_search_index() -> None:
    initialize_graph_schema()

    with connection() as db:
        db.executescript(
            FTS_SCHEMA
        )
        db.commit()


def rebuild_search_index() -> dict[str, Any]:
    initialize_search_index()

    with connection() as db:
        db.execute(
            """
            DELETE FROM organization_name_fts
            """
        )

        rows = db.execute(
            """
            SELECT
                gn.node_id,
                gn.name,
                gn.normalized_name,
                gn.name_type,
                gn.source_name,
                gn.confidence

            FROM organization_graph_names gn

            JOIN organization_graph_nodes n
              ON n.id = gn.node_id

            WHERE n.active = 1
            """
        ).fetchall()

        inserted = 0

        for row in rows:
            name = str(
                row[
                    "name"
                ]
            )

            normalized = str(
                row[
                    "normalized_name"
                ]
            )

            core = organization_core_name(
                name
            )

            db.execute(
                """
                INSERT INTO organization_name_fts (
                    name,
                    normalized_name,
                    core_name,
                    node_id,
                    name_type,
                    source_name,
                    confidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    normalized,
                    core,
                    int(
                        row[
                            "node_id"
                        ]
                    ),
                    row[
                        "name_type"
                    ],
                    row[
                        "source_name"
                    ],
                    float(
                        row[
                            "confidence"
                        ]
                        or 0.0
                    ),
                ),
            )

            inserted += 1

        db.commit()

    return {
        "records_indexed": inserted,
    }


def safe_fts_query(
    value: str,
) -> str:
    normalized = normalize_organization_name(
        value
    )

    tokens = re.findall(
        r"[a-z0-9]+",
        normalized,
    )

    if not tokens:
        return ""

    return " AND ".join(
        f'"{token}"'
        for token in tokens
    )


def search_organizations(
    value: str,
    *,
    limit: int = 25,
) -> list[dict[str, Any]]:
    initialize_search_index()

    query = safe_fts_query(
        value
    )

    if not query:
        return []

    with connection() as db:
        rows = db.execute(
            """
            SELECT
                CAST(
                    f.node_id
                    AS INTEGER
                ) AS node_id,

                f.name AS matched_name,
                f.normalized_name,
                f.core_name,
                f.name_type,
                f.source_name,

                CAST(
                    f.confidence
                    AS REAL
                ) AS name_confidence,

                bm25(
                    organization_name_fts
                ) AS search_rank,

                n.canonical_name,
                n.entity_type,
                n.country_code,
                n.confidence AS node_confidence

            FROM organization_name_fts f

            JOIN organization_graph_nodes n
              ON n.id =
                 CAST(
                     f.node_id
                     AS INTEGER
                 )

            WHERE organization_name_fts
                  MATCH ?

            ORDER BY
                search_rank ASC,
                name_confidence DESC

            LIMIT ?
            """,
            (
                query,
                int(limit),
            ),
        ).fetchall()

    seen = set()
    results = []

    for row in rows:
        node_id = int(
            row[
                "node_id"
            ]
        )

        if node_id in seen:
            continue

        seen.add(
            node_id
        )

        results.append(
            dict(row)
        )

    return results
