from __future__ import annotations

from app.global_entity_registry.ingestion.website_relationship_store import (
    initialize_relationship_schema,
)
from app.global_entity_registry.database import (
    connection,
)


def test_relationship_table_exists():
    initialize_relationship_schema()

    with connection() as db:
        row = db.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'entity_website_relationships'
            """
        ).fetchone()

    assert row is not None
