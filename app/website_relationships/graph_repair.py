from __future__ import annotations

from typing import Any

from app.global_entity_registry.database import (
    connection,
)
from app.website_relationships.classifier import (
    classify_website_relationship,
)


def ensure_schema() -> None:
    with connection() as db:
        columns = {
            row["name"]
            for row in db.execute(
                """
                PRAGMA table_info(
                    organization_graph_domains
                )
                """
            ).fetchall()
        }

        additions = {
            "website_relationship_type": (
                "TEXT"
            ),
            "platform_provider": (
                "TEXT"
            ),
            "platform_suffix": (
                "TEXT"
            ),
        }

        for column, definition in (
            additions.items()
        ):
            if column in columns:
                continue

            db.execute(
                f"""
                ALTER TABLE organization_graph_domains
                ADD COLUMN {column} {definition}
                """
            )

        db.commit()


def classify_existing_claims() -> dict[str, int]:
    ensure_schema()

    reviewed = 0
    platform_relationships = 0
    official_candidates = 0

    with connection() as db:
        rows = db.execute(
            """
            SELECT
                id,
                domain
            FROM organization_graph_domains
            """
        ).fetchall()

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

            eligible = bool(
                result[
                    "eligible_as_official_domain"
                ]
            )

            db.execute(
                """
                UPDATE organization_graph_domains

                SET
                    website_relationship_type = ?,
                    platform_provider = ?,
                    platform_suffix = ?,

                    usable_for_identity =
                        CASE
                            WHEN ? = 1
                            THEN usable_for_identity
                            ELSE 0
                        END,

                    integrity_state =
                        CASE
                            WHEN ? = 1
                            THEN integrity_state
                            ELSE 'platform_relationship'
                        END,

                    integrity_reason =
                        CASE
                            WHEN ? = 1
                            THEN integrity_reason
                            ELSE ?
                        END

                WHERE id = ?
                """,
                (
                    result[
                        "relationship_type"
                    ],
                    result.get(
                        "provider"
                    ),
                    result.get(
                        "platform_suffix"
                    ),
                    int(
                        eligible
                    ),
                    int(
                        eligible
                    ),
                    int(
                        eligible
                    ),
                    (
                        result.get(
                            "reason"
                        )
                    ),
                    int(
                        row[
                            "id"
                        ]
                    ),
                ),
            )

            reviewed += 1

            if eligible:
                official_candidates += 1
            else:
                platform_relationships += 1

        db.commit()

    return {
        "reviewed": reviewed,
        "official_candidates": (
            official_candidates
        ),
        "platform_relationships": (
            platform_relationships
        ),
    }


if __name__ == "__main__":
    from pprint import pprint

    pprint(
        classify_existing_claims(),
        sort_dicts=False,
    )
