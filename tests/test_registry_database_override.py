from __future__ import annotations

from pathlib import Path

from app.global_entity_registry.models import (
    EntityRecord,
)
from app.global_entity_registry.repository import (
    upsert_entity,
)
from app.global_entity_registry.database import (
    DEFAULT_DATABASE_PATH,
    active_database_path,
    connection,
    using_database,
)


def test_default_database_remains_production_path():
    assert (
        active_database_path()
        == DEFAULT_DATABASE_PATH
    )


def test_context_override_changes_active_path(
    tmp_path: Path,
):
    rehearsal = (
        tmp_path
        / "rehearsal.db"
    )

    with using_database(
        rehearsal
    ):
        assert (
            active_database_path()
            == rehearsal
        )

    assert (
        active_database_path()
        == DEFAULT_DATABASE_PATH
    )


def test_connection_uses_override(
    tmp_path: Path,
):
    rehearsal = (
        tmp_path
        / "isolated.db"
    )

    with using_database(
        rehearsal
    ):
        upsert_entity(
            EntityRecord(
                canonical_name="Isolation Test",
                domains=[
                    "isolation-test.example",
                ],
            )
        )

        with connection() as db:
            count = db.execute(
                """
                SELECT COUNT(*)
                FROM entities
                WHERE canonical_name = 'Isolation Test'
                """
            ).fetchone()[0]

    assert rehearsal.exists()
    assert count == 1

def test_nested_override_restores_parent(
    tmp_path: Path,
):
    first = (
        tmp_path
        / "first.db"
    )

    second = (
        tmp_path
        / "second.db"
    )

    with using_database(
        first
    ):
        assert (
            active_database_path()
            == first
        )

        with using_database(
            second
        ):
            assert (
                active_database_path()
                == second
            )

        assert (
            active_database_path()
            == first
        )

    assert (
        active_database_path()
        == DEFAULT_DATABASE_PATH
    )
