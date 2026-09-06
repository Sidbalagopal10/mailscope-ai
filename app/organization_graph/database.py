from __future__ import annotations

from app.global_entity_registry.database import (
    connection,
)


SCHEMA = """
CREATE TABLE IF NOT EXISTS organization_graph_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    registry_entity_id INTEGER,

    node_type TEXT NOT NULL,
    canonical_name TEXT NOT NULL,

    normalized_name TEXT,

    country_code TEXT,
    entity_type TEXT,

    confidence REAL NOT NULL DEFAULT 0.0,

    active INTEGER NOT NULL DEFAULT 1,

    UNIQUE (
        registry_entity_id,
        node_type
    )
);

CREATE TABLE IF NOT EXISTS organization_graph_names (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    node_id INTEGER NOT NULL,

    name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,

    name_type TEXT NOT NULL,

    source_name TEXT,

    confidence REAL NOT NULL DEFAULT 0.0,

    FOREIGN KEY (node_id)
        REFERENCES organization_graph_nodes(id)
        ON DELETE CASCADE,

    UNIQUE (
        node_id,
        normalized_name,
        name_type
    )
);

CREATE TABLE IF NOT EXISTS organization_graph_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    node_id INTEGER NOT NULL,

    domain TEXT NOT NULL,
    registrable_domain TEXT,

    relationship_type TEXT NOT NULL,

    confidence REAL NOT NULL DEFAULT 0.0,

    source_count INTEGER NOT NULL DEFAULT 0,

    verification_state TEXT,

    FOREIGN KEY (node_id)
        REFERENCES organization_graph_nodes(id)
        ON DELETE CASCADE,

    UNIQUE (
        node_id,
        domain
    )
);

CREATE TABLE IF NOT EXISTS organization_graph_identifiers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    node_id INTEGER NOT NULL,

    identifier_type TEXT NOT NULL,
    identifier_value TEXT NOT NULL,

    source_name TEXT,

    FOREIGN KEY (node_id)
        REFERENCES organization_graph_nodes(id)
        ON DELETE CASCADE,

    UNIQUE (
        node_id,
        identifier_type,
        identifier_value
    )
);

CREATE TABLE IF NOT EXISTS organization_graph_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    source_node_id INTEGER NOT NULL,
    target_node_id INTEGER NOT NULL,

    relationship_type TEXT NOT NULL,

    confidence REAL NOT NULL DEFAULT 0.0,

    source_name TEXT,
    evidence TEXT,

    FOREIGN KEY (source_node_id)
        REFERENCES organization_graph_nodes(id)
        ON DELETE CASCADE,

    FOREIGN KEY (target_node_id)
        REFERENCES organization_graph_nodes(id)
        ON DELETE CASCADE,

    UNIQUE (
        source_node_id,
        target_node_id,
        relationship_type
    )
);

CREATE INDEX IF NOT EXISTS idx_graph_node_name
ON organization_graph_nodes(normalized_name);

CREATE INDEX IF NOT EXISTS idx_graph_names_normalized
ON organization_graph_names(normalized_name);

CREATE INDEX IF NOT EXISTS idx_graph_domains_domain
ON organization_graph_domains(domain);

CREATE INDEX IF NOT EXISTS idx_graph_identifiers_value
ON organization_graph_identifiers(
    identifier_type,
    identifier_value
);

CREATE INDEX IF NOT EXISTS idx_graph_edges_source
ON organization_graph_edges(source_node_id);

CREATE INDEX IF NOT EXISTS idx_graph_edges_target
ON organization_graph_edges(target_node_id);
"""


def initialize_graph_schema() -> None:
    with connection() as db:
        db.executescript(
            SCHEMA
        )

        db.commit()


if __name__ == "__main__":
    initialize_graph_schema()

    print(
        "Organization graph schema initialized."
    )
