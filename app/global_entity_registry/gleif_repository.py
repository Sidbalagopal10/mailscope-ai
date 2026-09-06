from __future__ import annotations

import json
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any

from app.global_entity_registry.database import (
    connection,
)
from app.global_entity_registry.gleif_database import (
    initialize_gleif_schema,
)


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def normalized_name(
    value: str | None,
) -> str:
    cleaned = (
        str(
            value or ""
        )
        .lower()
        .strip()
    )

    characters = []

    for character in cleaned:
        if (
            character.isalnum()
            or character.isspace()
        ):
            characters.append(
                character
            )
        else:
            characters.append(
                " "
            )

    return " ".join(
        "".join(
            characters
        ).split()
    )


def name_similarity(
    left: str,
    right: str,
) -> float:
    first = normalized_name(
        left
    )

    second = normalized_name(
        right
    )

    if not first or not second:
        return 0.0

    if first == second:
        return 1.0

    return round(
        SequenceMatcher(
            None,
            first,
            second,
        ).ratio(),
        4,
    )


def upsert_legal_entity(
    record: dict[str, Any],
    *,
    entity_id: int | None = None,
) -> int:
    initialize_gleif_schema()

    now = utc_now()

    with connection() as db:
        existing = db.execute(
            """
            SELECT id
            FROM legal_entity_profiles
            WHERE lei = ?
            """,
            (
                record[
                    "lei"
                ],
            ),
        ).fetchone()

        fields = (
            entity_id,
            record[
                "legal_name"
            ],
            record.get(
                "legal_name_language"
            ),
            record.get(
                "entity_status"
            ),
            record.get(
                "jurisdiction"
            ),
            record.get(
                "legal_form_code"
            ),
            record.get(
                "registration_authority_id"
            ),
            record.get(
                "registration_authority_entity_id"
            ),
            record.get(
                "headquarters_country"
            ),
            record.get(
                "headquarters_region"
            ),
            record.get(
                "headquarters_city"
            ),
            record.get(
                "legal_address_country"
            ),
            record.get(
                "legal_address_region"
            ),
            record.get(
                "legal_address_city"
            ),
            record.get(
                "initial_registration_date"
            ),
            record.get(
                "last_update_date"
            ),
            record.get(
                "next_renewal_date"
            ),
            record.get(
                "managing_lou"
            ),
            now,
        )

        if existing:
            profile_id = int(
                existing[
                    "id"
                ]
            )

            db.execute(
                """
                UPDATE legal_entity_profiles
                SET
                    entity_id = COALESCE(?, entity_id),
                    legal_name = ?,
                    legal_name_language = ?,
                    entity_status = ?,
                    jurisdiction = ?,
                    legal_form_code = ?,
                    registration_authority_id = ?,
                    registration_authority_entity_id = ?,
                    headquarters_country = ?,
                    headquarters_region = ?,
                    headquarters_city = ?,
                    legal_address_country = ?,
                    legal_address_region = ?,
                    legal_address_city = ?,
                    initial_registration_date = ?,
                    last_update_date = ?,
                    next_renewal_date = ?,
                    managing_lou = ?,
                    imported_at = ?
                WHERE id = ?
                """,
                (
                    *fields,
                    profile_id,
                ),
            )

        else:
            cursor = db.execute(
                """
                INSERT INTO legal_entity_profiles (
                    entity_id,
                    lei,
                    legal_name,
                    legal_name_language,
                    entity_status,
                    jurisdiction,
                    legal_form_code,
                    registration_authority_id,
                    registration_authority_entity_id,
                    headquarters_country,
                    headquarters_region,
                    headquarters_city,
                    legal_address_country,
                    legal_address_region,
                    legal_address_city,
                    initial_registration_date,
                    last_update_date,
                    next_renewal_date,
                    managing_lou,
                    imported_at
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    entity_id,
                    record[
                        "lei"
                    ],
                    record[
                        "legal_name"
                    ],
                    record.get(
                        "legal_name_language"
                    ),
                    record.get(
                        "entity_status"
                    ),
                    record.get(
                        "jurisdiction"
                    ),
                    record.get(
                        "legal_form_code"
                    ),
                    record.get(
                        "registration_authority_id"
                    ),
                    record.get(
                        "registration_authority_entity_id"
                    ),
                    record.get(
                        "headquarters_country"
                    ),
                    record.get(
                        "headquarters_region"
                    ),
                    record.get(
                        "headquarters_city"
                    ),
                    record.get(
                        "legal_address_country"
                    ),
                    record.get(
                        "legal_address_region"
                    ),
                    record.get(
                        "legal_address_city"
                    ),
                    record.get(
                        "initial_registration_date"
                    ),
                    record.get(
                        "last_update_date"
                    ),
                    record.get(
                        "next_renewal_date"
                    ),
                    record.get(
                        "managing_lou"
                    ),
                    now,
                ),
            )

            profile_id = int(
                cursor.lastrowid
            )

        db.execute(
            """
            INSERT OR IGNORE INTO legal_entity_names (
                legal_entity_profile_id,
                name,
                name_type,
                language_code
            )
            VALUES (?, ?, 'legal_name', ?)
            """,
            (
                profile_id,
                record[
                    "legal_name"
                ],
                record.get(
                    "legal_name_language"
                ),
            ),
        )

        for other_name in record.get(
            "other_names",
            []
        ):
            db.execute(
                """
                INSERT OR IGNORE INTO legal_entity_names (
                    legal_entity_profile_id,
                    name,
                    name_type,
                    language_code
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    profile_id,
                    other_name[
                        "name"
                    ],
                    other_name.get(
                        "type"
                    )
                    or "other",
                    other_name.get(
                        "language"
                    ),
                ),
            )

        registration_id = record.get(
            "registration_authority_entity_id"
        )

        if registration_id:
            db.execute(
                """
                INSERT OR IGNORE INTO
                    legal_entity_registration_ids (
                        legal_entity_profile_id,
                        identifier_type,
                        identifier_value,
                        authority
                    )
                VALUES (
                    ?,
                    'business_registry',
                    ?,
                    ?
                )
                """,
                (
                    profile_id,
                    registration_id,
                    record.get(
                        "registration_authority_id"
                    ),
                ),
            )

        db.commit()

        return profile_id


def legal_entity_summary() -> dict[str, Any]:
    initialize_gleif_schema()

    with connection() as db:
        total = db.execute(
            """
            SELECT COUNT(*)
            FROM legal_entity_profiles
            """
        ).fetchone()[0]

        active = db.execute(
            """
            SELECT COUNT(*)
            FROM legal_entity_profiles
            WHERE UPPER(
                COALESCE(entity_status, '')
            ) = 'ACTIVE'
            """
        ).fetchone()[0]

        countries = db.execute(
            """
            SELECT COUNT(
                DISTINCT legal_address_country
            )
            FROM legal_entity_profiles
            WHERE legal_address_country IS NOT NULL
            """
        ).fetchone()[0]

        linked = db.execute(
            """
            SELECT COUNT(*)
            FROM legal_entity_profiles
            WHERE entity_id IS NOT NULL
            """
        ).fetchone()[0]

    return {
        "legal_entities": int(
            total
        ),
        "active_legal_entities": int(
            active
        ),
        "countries": int(
            countries
        ),
        "linked_registry_entities": int(
            linked
        ),
    }
