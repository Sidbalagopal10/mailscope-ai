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


def lookup_domain(
    domain: str,
) -> list[dict[str, Any]]:
    initialize_graph_schema()

    value = str(
        domain
    ).lower().strip().rstrip(".")

    with connection() as db:
        rows = db.execute(
            """
            SELECT
                n.id AS node_id,
                n.canonical_name,
                n.entity_type,
                n.country_code,

                d.domain,
                d.relationship_type,
                d.confidence,
                d.source_count

            FROM organization_graph_domains d

            JOIN organization_graph_nodes n
              ON n.id = d.node_id

            WHERE d.domain = ?
            """,
            (
                value,
            ),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


def lookup_name(
    name: str,
    *,
    limit: int = 25,
) -> list[dict[str, Any]]:
    initialize_graph_schema()

    normalized = (
        normalize_organization_name(
            name
        )
    )

    if not normalized:
        return []

    with connection() as db:
        rows = db.execute(
            """
            SELECT
                n.id AS node_id,
                n.canonical_name,
                n.entity_type,
                n.country_code,

                gn.name AS matched_name,
                gn.name_type,
                gn.source_name,
                gn.confidence

            FROM organization_graph_names gn

            JOIN organization_graph_nodes n
              ON n.id = gn.node_id

            WHERE gn.normalized_name = ?

            ORDER BY
                gn.confidence DESC

            LIMIT ?
            """,
            (
                normalized,
                int(limit),
            ),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


def organization_profile(
    node_id: int,
) -> dict[str, Any] | None:
    initialize_graph_schema()

    with connection() as db:
        node = db.execute(
            """
            SELECT *
            FROM organization_graph_nodes
            WHERE id = ?
            """,
            (
                int(node_id),
            ),
        ).fetchone()

        if node is None:
            return None

        names = db.execute(
            """
            SELECT *
            FROM organization_graph_names
            WHERE node_id = ?
            ORDER BY confidence DESC
            """,
            (
                int(node_id),
            ),
        ).fetchall()

        domains = db.execute(
            """
            SELECT *
            FROM organization_graph_domains
            WHERE node_id = ?
            ORDER BY
                source_count DESC,
                confidence DESC
            """,
            (
                int(node_id),
            ),
        ).fetchall()

        identifiers = db.execute(
            """
            SELECT *
            FROM organization_graph_identifiers
            WHERE node_id = ?
            """,
            (
                int(node_id),
            ),
        ).fetchall()

    return {
        "organization": dict(
            node
        ),
        "names": [
            dict(row)
            for row in names
        ],
        "domains": [
            dict(row)
            for row in domains
        ],
        "identifiers": [
            dict(row)
            for row in identifiers
        ],
    }


def graph_summary() -> dict[str, int]:
    initialize_graph_schema()

    with connection() as db:
        nodes = db.execute(
            """
            SELECT COUNT(*)
            FROM organization_graph_nodes
            """
        ).fetchone()[0]

        names = db.execute(
            """
            SELECT COUNT(*)
            FROM organization_graph_names
            """
        ).fetchone()[0]

        domains = db.execute(
            """
            SELECT COUNT(*)
            FROM organization_graph_domains
            """
        ).fetchone()[0]

        identifiers = db.execute(
            """
            SELECT COUNT(*)
            FROM organization_graph_identifiers
            """
        ).fetchone()[0]

        edges = db.execute(
            """
            SELECT COUNT(*)
            FROM organization_graph_edges
            """
        ).fetchone()[0]

    return {
        "nodes": int(
            nodes
        ),
        "names": int(
            names
        ),
        "domains": int(
            domains
        ),
        "identifiers": int(
            identifiers
        ),
        "edges": int(
            edges
        ),
    }
