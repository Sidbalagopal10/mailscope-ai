from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tqdm import tqdm

from app.global_entity_registry.database import (
    connection,
)
from app.global_entity_registry.ingestors.ror_downloader import (
    download_latest_ror_dump,
    load_ror_records,
)
from app.global_entity_registry.ingestors.ror_parser import (
    parse_ror_record,
)
from app.global_entity_registry.repository import (
    registry_summary,
    upsert_entity,
)


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def import_ror(
    *,
    zip_path: Path | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    if zip_path is None:
        zip_path = (
            download_latest_ror_dump()
        )

    records = load_ror_records(
        zip_path
    )

    if limit is not None:
        records = records[
            :limit
        ]

    started = utc_now()

    with connection() as db:
        cursor = db.execute(
            """
            INSERT INTO ingestion_runs (
                source_name,
                started_at,
                status
            )
            VALUES (?, ?, 'running')
            """,
            (
                "ror",
                started,
            ),
        )

        run_id = int(
            cursor.lastrowid
        )

        db.commit()

    seen = 0
    imported = 0
    skipped = 0
    errors = 0

    before = registry_summary()

    for raw_record in tqdm(
        records,
        desc="Importing ROR",
        unit="org",
    ):
        seen += 1

        try:
            parsed = parse_ror_record(
                raw_record
            )

            if parsed is None:
                skipped += 1
                continue

            # Records without domains are still useful for entity
            # aliases and external IDs.
            upsert_entity(
                parsed
            )

            imported += 1

        except Exception:
            errors += 1

    after = registry_summary()

    completed = utc_now()

    entities_created = max(
        0,
        int(
            after[
                "entities"
            ]
        )
        - int(
            before[
                "entities"
            ]
        ),
    )

    domains_created = max(
        0,
        int(
            after[
                "domains"
            ]
        )
        - int(
            before[
                "domains"
            ]
        ),
    )

    with connection() as db:
        db.execute(
            """
            UPDATE ingestion_runs
            SET
                completed_at = ?,
                records_seen = ?,
                entities_created = ?,
                domains_created = ?,
                errors = ?,
                status = ?
            WHERE id = ?
            """,
            (
                completed,
                seen,
                entities_created,
                domains_created,
                errors,
                (
                    "completed"
                    if errors == 0
                    else "completed_with_errors"
                ),
                run_id,
            ),
        )

        db.commit()

    return {
        "source": "ror",
        "zip_path": str(
            zip_path
        ),
        "records_seen": seen,
        "records_imported": imported,
        "records_skipped": skipped,
        "errors": errors,
        "entities_created": (
            entities_created
        ),
        "domains_created": domains_created,
        "registry_summary": after,
    }


if __name__ == "__main__":
    result = import_ror()

    print()
    print("=" * 70)

    for key, value in result.items():
        print(
            f"{key}: {value}"
        )
