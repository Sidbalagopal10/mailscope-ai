from __future__ import annotations

from typing import Any

from app.global_entity_registry.database import (
    connection,
)
from app.organization_graph.database import (
    initialize_graph_schema,
)
from app.organization_graph.normalization import (
    normalize_organization_name,
)


def build_graph(
    *,
    limit: int | None = None,
    reset: bool = False,
) -> dict[str, Any]:
    initialize_graph_schema()

    with connection() as db:
        if reset:
            db.execute(
                "DELETE FROM organization_graph_edges"
            )
            db.execute(
                "DELETE FROM organization_graph_identifiers"
            )
            db.execute(
                "DELETE FROM organization_graph_domains"
            )
            db.execute(
                "DELETE FROM organization_graph_names"
            )
            db.execute(
                "DELETE FROM organization_graph_nodes"
            )

            db.commit()

        query = """
            SELECT
                id,
                canonical_name,
                entity_type,
                country_code
            FROM entities
            ORDER BY id
        """

        parameters = ()

        if limit is not None:
            query += " LIMIT ?"
            parameters = (
                int(limit),
            )

        entities = db.execute(
            query,
            parameters,
        ).fetchall()

    processed = 0
    names_added = 0
    domains_added = 0
    identifiers_added = 0

    for entity in entities:
        entity_id = int(
            entity[
                "id"
            ]
        )

        canonical_name = str(
            entity[
                "canonical_name"
            ]
        )

        normalized = normalize_organization_name(
            canonical_name
        )

        with connection() as db:
            existing_node = db.execute(
                """
                SELECT id
                FROM organization_graph_nodes
                WHERE registry_entity_id = ?
                  AND node_type = 'organization'
                """,
                (
                    entity_id,
                ),
            ).fetchone()

            if existing_node:
                node_id = int(
                    existing_node[
                        "id"
                    ]
                )

            else:
                cursor = db.execute(
                    """
                    INSERT INTO organization_graph_nodes (
                        registry_entity_id,
                        node_type,
                        canonical_name,
                        normalized_name,
                        country_code,
                        entity_type,
                        confidence,
                        active
                    )
                    VALUES (
                        ?,
                        'organization',
                        ?,
                        ?,
                        ?,
                        ?,
                        0.80,
                        1
                    )
                    """,
                    (
                        entity_id,
                        canonical_name,
                        normalized,
                        entity[
                            "country_code"
                        ],
                        entity[
                            "entity_type"
                        ],
                    ),
                )

                node_id = int(
                    cursor.lastrowid
                )

            db.execute(
                """
                INSERT OR IGNORE INTO organization_graph_names (
                    node_id,
                    name,
                    normalized_name,
                    name_type,
                    source_name,
                    confidence
                )
                VALUES (
                    ?,
                    ?,
                    ?,
                    'canonical',
                    'global_entity_registry',
                    0.95
                )
                """,
                (
                    node_id,
                    canonical_name,
                    normalized,
                ),
            )

            names_added += 1

            aliases = db.execute(
                """
                SELECT
                    alias,
                    source_name
                FROM entity_aliases
                WHERE entity_id = ?
                """,
                (
                    entity_id,
                ),
            ).fetchall()

            for alias in aliases:
                alias_name = str(
                    alias[
                        "alias"
                    ]
                )

                alias_normalized = (
                    normalize_organization_name(
                        alias_name
                    )
                )

                if not alias_normalized:
                    continue

                db.execute(
                    """
                    INSERT OR IGNORE INTO organization_graph_names (
                        node_id,
                        name,
                        normalized_name,
                        name_type,
                        source_name,
                        confidence
                    )
                    VALUES (
                        ?,
                        ?,
                        ?,
                        'alias',
                        ?,
                        0.80
                    )
                    """,
                    (
                        node_id,
                        alias_name,
                        alias_normalized,
                        alias[
                            "source_name"
                        ],
                    ),
                )

                names_added += 1

            domains = db.execute(
                """
                SELECT
                    d.id,
                    d.domain,
                    d.registrable_domain,
                    d.confidence,
                    d.verification_state,
                    COUNT(
                        DISTINCT es.source_name
                    ) AS source_count
                FROM domains d

                LEFT JOIN evidence_sources es
                  ON es.domain_id = d.id

                WHERE d.entity_id = ?
                  AND d.active = 1

                GROUP BY d.id
                """,
                (
                    entity_id,
                ),
            ).fetchall()

            for domain in domains:
                source_count = int(
                    domain[
                        "source_count"
                    ]
                    or 0
                )

                relationship_type = (
                    "verified_official_domain"
                    if source_count >= 2
                    else "supported_official_domain"
                )

                db.execute(
                    """
                    INSERT INTO organization_graph_domains (
                        node_id,
                        domain,
                        registrable_domain,
                        relationship_type,
                        confidence,
                        source_count,
                        verification_state
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)

                    ON CONFLICT(
                        node_id,
                        domain
                    )
                    DO UPDATE SET
                        registrable_domain =
                            excluded.registrable_domain,
                        relationship_type =
                            excluded.relationship_type,
                        confidence =
                            excluded.confidence,
                        source_count =
                            excluded.source_count,
                        verification_state =
                            excluded.verification_state
                    """,
                    (
                        node_id,
                        domain[
                            "domain"
                        ],
                        domain[
                            "registrable_domain"
                        ],
                        relationship_type,
                        float(
                            domain[
                                "confidence"
                            ]
                            or 0.0
                        ),
                        source_count,
                        domain[
                            "verification_state"
                        ],
                    ),
                )

                domains_added += 1

            identifiers = db.execute(
                """
                SELECT
                    identifier_type,
                    identifier_value
                FROM external_identifiers
                WHERE entity_id = ?
                """,
                (
                    entity_id,
                ),
            ).fetchall()

            for identifier in identifiers:
                db.execute(
                    """
                    INSERT OR IGNORE INTO
                    organization_graph_identifiers (
                        node_id,
                        identifier_type,
                        identifier_value,
                        source_name
                    )
                    VALUES (?, ?, ?, 'global_entity_registry')
                    """,
                    (
                        node_id,
                        identifier[
                            "identifier_type"
                        ],
                        identifier[
                            "identifier_value"
                        ],
                    ),
                )

                identifiers_added += 1

            db.commit()

        processed += 1

        if processed % 5000 == 0:
            print(
                f"{processed:,} organizations processed"
            )

    return {
        "organizations_processed": processed,
        "names_processed": names_added,
        "domains_processed": domains_added,
        "identifiers_processed": (
            identifiers_added
        ),
    }


if __name__ == "__main__":
    from pprint import pprint

    pprint(
        build_graph(),
        sort_dicts=False,
    )
