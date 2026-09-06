from __future__ import annotations

import sqlite3
from typing import Iterable

from app.global_entity_registry.database import (
    connection,
)
from app.global_entity_registry.models import (
    WebsiteRelationship,
)


SCHEMA = """
CREATE TABLE IF NOT EXISTS entity_website_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    entity_id INTEGER NOT NULL,

    original_value TEXT NOT NULL,
    hostname TEXT NOT NULL,

    relationship_type TEXT NOT NULL,

    eligible_for_domain_identity INTEGER
        NOT NULL DEFAULT 0,

    preserve_as_relationship INTEGER
        NOT NULL DEFAULT 1,

    provider TEXT,
    platform_suffix TEXT,

    confidence REAL NOT NULL DEFAULT 0.50,

    source_name TEXT NOT NULL DEFAULT '',
    source_record_id TEXT NOT NULL DEFAULT '',

    reason TEXT,

    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,

    active INTEGER NOT NULL DEFAULT 1,

    FOREIGN KEY (entity_id)
        REFERENCES entities(id)
        ON DELETE CASCADE,

    UNIQUE (
        entity_id,
        original_value,
        relationship_type,
        source_name,
        source_record_id
    )
);

CREATE INDEX IF NOT EXISTS
idx_entity_website_relationships_entity
ON entity_website_relationships(entity_id);

CREATE INDEX IF NOT EXISTS
idx_entity_website_relationships_hostname
ON entity_website_relationships(hostname);

CREATE INDEX IF NOT EXISTS
idx_entity_website_relationships_type
ON entity_website_relationships(relationship_type);
"""


def initialize_relationship_schema(
    db: sqlite3.Connection | None = None,
) -> None:
    """
    Initialize schema.

    If an existing connection is supplied, use it.
    This prevents nested SQLite write connections.
    """

    if db is not None:
        db.executescript(
            SCHEMA
        )

        return

    with connection() as local_db:
        local_db.executescript(
            SCHEMA
        )

        local_db.commit()


def _upsert_relationship_on_connection(
    *,
    db: sqlite3.Connection,
    entity_id: int,
    relationship: WebsiteRelationship,
    observed_at: str,
) -> bool:
    if not relationship.preserve_as_relationship:
        return False

    if not relationship.hostname:
        return False

    source_name = str(
        relationship.source_name
        or ""
    )

    source_record_id = str(
        relationship.source_record_id
        or ""
    )

    db.execute(
        """
        INSERT INTO entity_website_relationships (
            entity_id,
            original_value,
            hostname,
            relationship_type,

            eligible_for_domain_identity,
            preserve_as_relationship,

            provider,
            platform_suffix,

            confidence,

            source_name,
            source_record_id,

            reason,

            first_seen_at,
            last_seen_at,
            active
        )
        VALUES (
            ?, ?, ?, ?,
            ?, ?,
            ?, ?,
            ?,
            ?, ?,
            ?,
            ?, ?,
            1
        )

        ON CONFLICT(
            entity_id,
            original_value,
            relationship_type,
            source_name,
            source_record_id
        )
        DO UPDATE SET
            hostname =
                excluded.hostname,

            eligible_for_domain_identity =
                excluded.eligible_for_domain_identity,

            preserve_as_relationship =
                excluded.preserve_as_relationship,

            provider =
                excluded.provider,

            platform_suffix =
                excluded.platform_suffix,

            confidence =
                MAX(
                    entity_website_relationships.confidence,
                    excluded.confidence
                ),

            reason =
                excluded.reason,

            last_seen_at =
                excluded.last_seen_at,

            active = 1
        """,
        (
            int(
                entity_id
            ),

            relationship.original_value,
            relationship.hostname,
            relationship.relationship_type,

            int(
                relationship.eligible_for_domain_identity
            ),

            int(
                relationship.preserve_as_relationship
            ),

            relationship.provider,
            relationship.platform_suffix,

            float(
                relationship.confidence
            ),

            source_name,
            source_record_id,

            relationship.reason,

            observed_at,
            observed_at,
        ),
    )

    return True


def upsert_website_relationship(
    *,
    entity_id: int,
    relationship: WebsiteRelationship,
    observed_at: str,
    db: sqlite3.Connection | None = None,
) -> None:
    if db is not None:
        _upsert_relationship_on_connection(
            db=db,
            entity_id=entity_id,
            relationship=relationship,
            observed_at=observed_at,
        )

        return

    with connection() as local_db:
        initialize_relationship_schema(
            local_db
        )

        _upsert_relationship_on_connection(
            db=local_db,
            entity_id=entity_id,
            relationship=relationship,
            observed_at=observed_at,
        )

        local_db.commit()


def upsert_website_relationships(
    *,
    entity_id: int,
    relationships: Iterable[
        WebsiteRelationship
    ],
    observed_at: str,
    db: sqlite3.Connection | None = None,
) -> int:
    """
    Persist many relationships.

    When db is provided, everything uses the caller's
    transaction and NO secondary SQLite connection opens.
    """

    if db is not None:
        count = 0

        for relationship in relationships:
            inserted = (
                _upsert_relationship_on_connection(
                    db=db,
                    entity_id=entity_id,
                    relationship=relationship,
                    observed_at=observed_at,
                )
            )

            if inserted:
                count += 1

        return count

    with connection() as local_db:
        initialize_relationship_schema(
            local_db
        )

        count = 0

        for relationship in relationships:
            inserted = (
                _upsert_relationship_on_connection(
                    db=local_db,
                    entity_id=entity_id,
                    relationship=relationship,
                    observed_at=observed_at,
                )
            )

            if inserted:
                count += 1

        local_db.commit()

        return count


def relationship_summary() -> dict[str, int]:
    initialize_relationship_schema()

    with connection() as db:
        total = db.execute(
            """
            SELECT COUNT(*)
            FROM entity_website_relationships
            """
        ).fetchone()[0]

        identity = db.execute(
            """
            SELECT COUNT(*)
            FROM entity_website_relationships
            WHERE eligible_for_domain_identity = 1
            """
        ).fetchone()[0]

        contextual = db.execute(
            """
            SELECT COUNT(*)
            FROM entity_website_relationships
            WHERE eligible_for_domain_identity = 0
            """
        ).fetchone()[0]

    return {
        "total": int(total),
        "identity_eligible": int(identity),
        "context_only": int(contextual),
    }
