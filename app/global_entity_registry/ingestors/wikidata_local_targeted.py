from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from app.global_entity_registry.database import (
    connection,
)
from app.global_entity_registry.ingestors.wikidata_dump_extractor import (
    iter_json_array_dump,
    qid,
)
from app.global_entity_registry.ingestors.wikidata_enricher import (
    add_alias,
    add_wikidata_domain,
    english_aliases,
    official_websites,
)


def rehearsal_wikidata_targets() -> dict[
    str,
    list[int],
]:
    """
    Map Wikidata QID -> existing registry entity IDs.
    """

    with connection() as db:
        rows = db.execute(
            """
            SELECT
                entity_id,
                identifier_value

            FROM external_identifiers

            WHERE LOWER(
                identifier_type
            ) = 'wikidata'
            """
        ).fetchall()

    targets: dict[
        str,
        list[int],
    ] = {}

    for row in rows:
        value = str(
            row[
                "identifier_value"
            ]
            or ""
        ).strip()

        if not value:
            continue

        normalized = (
            value
            if value.startswith("Q")
            else "Q" + value
        )

        targets.setdefault(
            normalized,
            [],
        ).append(
            int(
                row[
                    "entity_id"
                ]
            )
        )

    return targets


def enrich_targets_from_local_dump(
    dump_path: Path,
    *,
    progress_every: int = 1_000_000,
) -> dict[str, Any]:
    targets = rehearsal_wikidata_targets()

    remaining = set(
        targets
    )

    started = time.time()

    entities_scanned = 0
    targets_found = 0

    websites_seen = 0
    domains_added = 0

    aliases_seen = 0
    aliases_added = 0

    errors = 0

    found_qids: list[str] = []

    print(
        "Target QIDs:",
        len(
            targets
        ),
    )

    for entity in iter_json_array_dump(
        dump_path
    ):
        entities_scanned += 1

        current_qid = qid(
            entity
        )

        if not current_qid:
            continue

        if current_qid not in remaining:
            if (
                progress_every
                and entities_scanned
                % progress_every
                == 0
            ):
                print(
                    f"{entities_scanned:,} dump entities scanned | "
                    f"{targets_found}/{len(targets)} targets found"
                )

            continue

        entity_ids = targets[
            current_qid
        ]

        websites = official_websites(
            entity
        )

        aliases = english_aliases(
            entity
        )

        print()
        print(
            "FOUND",
            current_qid,
            "| entity IDs:",
            entity_ids,
            "| websites:",
            len(
                websites
            ),
            "| aliases:",
            len(
                aliases
            ),
        )

        for entity_id in entity_ids:
            for alias in aliases:
                aliases_seen += 1

                try:
                    add_alias(
                        entity_id=entity_id,
                        alias=alias,
                    )

                    aliases_added += 1

                except Exception as error:
                    errors += 1

                    print(
                        "Alias error:",
                        current_qid,
                        alias,
                        repr(
                            error
                        ),
                    )

            for website in websites:
                websites_seen += 1

                try:
                    added = add_wikidata_domain(
                        entity_id=entity_id,
                        qid=current_qid,
                        website_url=website,
                    )

                    if added:
                        domains_added += 1

                except Exception as error:
                    errors += 1

                    print(
                        "Website error:",
                        current_qid,
                        website,
                        repr(
                            error
                        ),
                    )

        remaining.remove(
            current_qid
        )

        found_qids.append(
            current_qid
        )

        targets_found += 1

        if not remaining:
            print()
            print(
                "✅ All target QIDs found. "
                "Stopping dump scan early."
            )

            break

    elapsed = (
        time.time()
        - started
    )

    return {
        "target_qids": len(
            targets
        ),

        "targets_found": targets_found,

        "targets_missing": len(
            remaining
        ),

        "missing_qids": sorted(
            remaining
        ),

        "found_qids": sorted(
            found_qids
        ),

        "dump_entities_scanned": (
            entities_scanned
        ),

        "websites_seen": websites_seen,

        "domains_added": domains_added,

        "aliases_seen": aliases_seen,

        "aliases_added": aliases_added,

        "errors": errors,

        "elapsed_seconds": round(
            elapsed,
            2,
        ),
    }
