from __future__ import annotations

import argparse
import time
from pathlib import Path
from pprint import pprint
from typing import Any

from app.global_entity_registry.gleif_database import (
    initialize_gleif_schema,
)
from app.global_entity_registry.gleif_repository import (
    legal_entity_summary,
    upsert_legal_entity,
)
from app.global_entity_registry.ingestors.gleif_bulk_downloader import (
    download_level1_zip,
)
from app.global_entity_registry.ingestors.gleif_bulk_parser import (
    iter_lei_records,
)


def import_level1(
    *,
    zip_path: Path | None = None,
    limit: int | None = None,
    progress_every: int = 10_000,
) -> dict[str, Any]:
    initialize_gleif_schema()

    if zip_path is None:
        zip_path = download_level1_zip()

    started = time.time()

    seen = 0
    imported = 0
    errors = 0

    for record in iter_lei_records(
        zip_path
    ):
        seen += 1

        try:
            upsert_legal_entity(
                record
            )

            imported += 1

        except Exception as error:
            errors += 1

            if errors <= 20:
                print(
                    "Import error:",
                    record.get(
                        "lei"
                    ),
                    repr(
                        error
                    ),
                )

        if (
            progress_every
            and seen
            % progress_every
            == 0
        ):
            elapsed = max(
                time.time()
                - started,
                0.001,
            )

            print(
                f"{seen:,} records | "
                f"{imported:,} imported | "
                f"{errors:,} errors | "
                f"{seen / elapsed:,.1f} records/sec"
            )

        if (
            limit is not None
            and seen >= limit
        ):
            break

    elapsed = (
        time.time()
        - started
    )

    return {
        "zip_path": str(
            zip_path
        ),
        "records_seen": seen,
        "records_imported": imported,
        "errors": errors,
        "elapsed_seconds": round(
            elapsed,
            2,
        ),
        "records_per_second": round(
            (
                seen / elapsed
                if elapsed > 0
                else 0
            ),
            2,
        ),
        "summary": (
            legal_entity_summary()
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--zip",
        type=Path,
        default=None,
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
    )

    args = parser.parse_args()

    pprint(
        import_level1(
            zip_path=args.zip,
            limit=args.limit,
        ),
        sort_dicts=False,
    )


if __name__ == "__main__":
    main()
