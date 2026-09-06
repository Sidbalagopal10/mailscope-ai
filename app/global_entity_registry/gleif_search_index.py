from __future__ import annotations

import re
from typing import Any

from app.global_entity_registry.database import connection
from app.global_entity_registry.gleif_database import (
    initialize_gleif_schema,
)


FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS gleif_name_fts
USING fts5(
    name,
    lei UNINDEXED,
    profile_id UNINDEXED,
    name_type UNINDEXED,
    tokenize='unicode61 remove_diacritics 2'
);
"""


def initialize_fts() -> None:
    initialize_gleif_schema()

    with connection() as db:
        db.executescript(
            FTS_SCHEMA
        )
        db.commit()


def build_fts(
    *,
    force: bool = False,
) -> dict[str, Any]:
    initialize_fts()

    with connection() as db:
        existing = db.execute(
            """
            SELECT COUNT(*)
            FROM gleif_name_fts
            """
        ).fetchone()[0]

        if existing and not force:
            return {
                "rebuilt": False,
                "records": int(existing),
            }

        if force:
            db.execute(
                "DELETE FROM gleif_name_fts"
            )

        print(
            "Building GLEIF full-text index..."
        )

        db.execute(
            """
            INSERT INTO gleif_name_fts (
                name,
                lei,
                profile_id,
                name_type
            )

            SELECT
                n.name,
                p.lei,
                p.id,
                n.name_type

            FROM legal_entity_names n

            JOIN legal_entity_profiles p
              ON p.id =
                 n.legal_entity_profile_id
            """
        )

        db.commit()

        total = db.execute(
            """
            SELECT COUNT(*)
            FROM gleif_name_fts
            """
        ).fetchone()[0]

    return {
        "rebuilt": True,
        "records": int(total),
    }


def fts_query(
    value: str,
) -> str:
    tokens = re.findall(
        r"\w+",
        str(value or ""),
        flags=re.UNICODE,
    )

    if not tokens:
        return ""

    # Phrase search first.
    phrase = " ".join(tokens)

    return (
        '"'
        + phrase.replace(
            '"',
            "",
        )
        + '"'
    )


def search_names(
    value: str,
    *,
    limit: int = 20,
) -> list[dict[str, Any]]:
    initialize_fts()

    query = fts_query(
        value
    )

    if not query:
        return []

    with connection() as db:
        rows = db.execute(
            """
            SELECT
                f.name,
                f.lei,
                f.profile_id,
                f.name_type,
                bm25(
                    gleif_name_fts
                ) AS search_rank,

                p.entity_status,
                p.jurisdiction,
                p.legal_address_country,
                p.headquarters_country

            FROM gleif_name_fts f

            JOIN legal_entity_profiles p
              ON p.id =
                 CAST(
                     f.profile_id
                     AS INTEGER
                 )

            WHERE gleif_name_fts
                  MATCH ?

            ORDER BY search_rank ASC

            LIMIT ?
            """,
            (
                query,
                int(limit),
            ),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]
