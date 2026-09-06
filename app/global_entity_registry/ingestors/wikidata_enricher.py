from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any, Iterable

import requests

from app.global_entity_registry.database import (
    connection,
)
from app.global_entity_registry.ingestion.relationship_builder import (
    build_website_relationship,
)
from app.global_entity_registry.ingestion.website_relationship_store import (
    upsert_website_relationship,
)
from app.global_entity_registry.ingestion.website_policy import (
    evaluate_website_for_ingestion,
)
from app.global_entity_registry.domain_utils import (
    canonical_identity_domain,
    normalize_hostname,
)
from app.global_entity_registry.public_suffix import (
    registrable_domain,
)


WIKIDATA_API = (
    "https://www.wikidata.org/w/api.php"
)

USER_AGENT = (
    "AI-Mail-Phishing-Detector/"
    "GlobalEntityRegistry/1.0 "
    "(identity enrichment; read-only)"
)

BATCH_SIZE = 50

QID_PATTERN = re.compile(
    r"\bQ\d+\b",
    re.IGNORECASE,
)


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def normalize_qid(
    value: str | None,
) -> str:
    match = QID_PATTERN.search(
        str(
            value or ""
        )
    )

    if not match:
        return ""

    return match.group(
        0
    ).upper()


def chunks(
    values: list[Any],
    size: int,
) -> Iterable[list[Any]]:
    for index in range(
        0,
        len(values),
        size,
    ):
        yield values[
            index:index + size
        ]


def registry_wikidata_links(
    *,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    with connection() as db:
        rows = db.execute(
            """
            SELECT
                ei.entity_id,
                ei.identifier_value,
                e.canonical_name

            FROM external_identifiers ei

            JOIN entities e
              ON e.id = ei.entity_id

            WHERE LOWER(ei.identifier_type) =
                  'wikidata'

            ORDER BY ei.entity_id
            """
        ).fetchall()

    results = []

    seen = set()

    for row in rows:
        qid = normalize_qid(
            row[
                "identifier_value"
            ]
        )

        if not qid:
            continue

        key = (
            int(
                row[
                    "entity_id"
                ]
            ),
            qid,
        )

        if key in seen:
            continue

        seen.add(
            key
        )

        results.append(
            {
                "entity_id": int(
                    row[
                        "entity_id"
                    ]
                ),
                "qid": qid,
                "canonical_name": (
                    row[
                        "canonical_name"
                    ]
                ),
            }
        )

    if limit is not None:
        return results[
            :limit
        ]

    return results


def fetch_entities(
    qids: list[str],
) -> dict[str, Any]:
    if not qids:
        return {}

    response = requests.get(
        WIKIDATA_API,
        params={
            "action": "wbgetentities",
            "ids": "|".join(
                qids
            ),
            "props": (
                "labels|aliases|claims"
            ),
            "languages": "en",
            "languagefallback": "1",
            "format": "json",
        },
        headers={
            "User-Agent": USER_AGENT,
        },
        timeout=60,
    )

    response.raise_for_status()

    payload = response.json()

    entities = payload.get(
        "entities",
        {}
    )

    return (
        entities
        if isinstance(
            entities,
            dict,
        )
        else {}
    )


def claim_strings(
    entity: dict[str, Any],
    property_id: str,
) -> list[str]:
    claims = entity.get(
        "claims",
        {},
    )

    statements = claims.get(
        property_id,
        [],
    )

    values = []

    if not isinstance(
        statements,
        list,
    ):
        return values

    for statement in statements:
        if not isinstance(
            statement,
            dict,
        ):
            continue

        mainsnak = statement.get(
            "mainsnak",
            {},
        )

        datavalue = mainsnak.get(
            "datavalue",
            {},
        )

        value = datavalue.get(
            "value"
        )

        if isinstance(
            value,
            str,
        ):
            cleaned = value.strip()

            if cleaned:
                values.append(
                    cleaned
                )

    return list(
        dict.fromkeys(
            values
        )
    )


def official_websites(
    entity: dict[str, Any],
) -> list[str]:
    # P856 = official website
    return claim_strings(
        entity,
        "P856",
    )


def english_aliases(
    entity: dict[str, Any],
) -> list[str]:
    aliases = entity.get(
        "aliases",
        {},
    )

    english = aliases.get(
        "en",
        [],
    )

    values = []

    if isinstance(
        english,
        list,
    ):
        for item in english:
            if not isinstance(
                item,
                dict,
            ):
                continue

            value = str(
                item.get(
                    "value",
                    "",
                )
            ).strip()

            if value:
                values.append(
                    value
                )

    return list(
        dict.fromkeys(
            values
        )
    )


def add_alias(
    *,
    entity_id: int,
    alias: str,
) -> None:
    cleaned = str(
        alias
    ).strip()

    if not cleaned:
        return

    with connection() as db:
        db.execute(
            """
            INSERT OR IGNORE INTO entity_aliases (
                entity_id,
                alias,
                language_code,
                source_name
            )
            VALUES (?, ?, 'en', 'wikidata')
            """,
            (
                entity_id,
                cleaned,
            ),
        )

        db.commit()


def add_wikidata_domain(
    *,
    entity_id: int,
    qid: str,
    website_url: str,
) -> bool:
    relationship = build_website_relationship(
        website_url,
        source_name="wikidata_p856",
        source_record_id=qid,
        confidence=0.82,
    )

    if relationship.hostname:
        upsert_website_relationship(
            entity_id=entity_id,
            relationship=relationship,
            observed_at=utc_now(),
        )

    if not (
        relationship.hostname
        and relationship.eligible_for_domain_identity
    ):
        return False

    hostname = canonical_identity_domain(
        relationship.hostname
    )

    if not hostname:
        return False

    registrable = registrable_domain(
        hostname
    )

    now = utc_now()

    with connection() as db:
        existing = db.execute(
            """
            SELECT id, confidence
            FROM domains
            WHERE entity_id = ?
              AND domain = ?
            """,
            (
                entity_id,
                hostname,
            ),
        ).fetchone()

        # P856 is strong evidence, but Wikidata itself documents that
        # former websites may remain. Therefore this is not treated as
        # absolute authority.
        wikidata_confidence = 0.82

        if existing:
            domain_id = int(
                existing[
                    "id"
                ]
            )

            existing_confidence = float(
                existing[
                    "confidence"
                ]
            )

            db.execute(
                """
                UPDATE domains
                SET
                    confidence = ?,
                    last_verified_at = ?
                WHERE id = ?
                """,
                (
                    max(
                        existing_confidence,
                        wikidata_confidence,
                    ),
                    now,
                    domain_id,
                ),
            )

        else:
            cursor = db.execute(
                """
                INSERT INTO domains (
                    entity_id,
                    domain,
                    registrable_domain,
                    relationship_type,
                    verification_state,
                    confidence,
                    first_seen_at,
                    last_verified_at,
                    active
                )
                VALUES (
                    ?, ?, ?,
                    'official_candidate',
                    'source_supported',
                    ?,
                    ?, ?,
                    1
                )
                """,
                (
                    entity_id,
                    hostname,
                    registrable,
                    wikidata_confidence,
                    now,
                    now,
                ),
            )

            domain_id = int(
                cursor.lastrowid
            )

        duplicate = db.execute(
            """
            SELECT id
            FROM evidence_sources
            WHERE domain_id = ?
              AND source_name = 'wikidata_p856'
              AND source_record_id = ?
              AND raw_reference = ?
            LIMIT 1
            """,
            (
                domain_id,
                qid,
                website_url,
            ),
        ).fetchone()

        if not duplicate:
            db.execute(
                """
                INSERT INTO evidence_sources (
                    domain_id,
                    source_name,
                    source_record_id,
                    source_url,
                    evidence_type,
                    confidence,
                    authoritative,
                    observed_at,
                    raw_reference
                )
                VALUES (
                    ?,
                    'wikidata_p856',
                    ?,
                    ?,
                    'official_website',
                    ?,
                    0,
                    ?,
                    ?
                )
                """,
                (
                    domain_id,
                    qid,
                    (
                        "https://www.wikidata.org/"
                        f"wiki/{qid}"
                    ),
                    wikidata_confidence,
                    now,
                    website_url,
                ),
            )

        db.commit()

    return True


def begin_ingestion_run() -> int:
    with connection() as db:
        cursor = db.execute(
            """
            INSERT INTO ingestion_runs (
                source_name,
                started_at,
                status
            )
            VALUES (
                'wikidata_p856',
                ?,
                'running'
            )
            """,
            (
                utc_now(),
            ),
        )

        run_id = int(
            cursor.lastrowid
        )

        db.commit()

        return run_id


def finish_ingestion_run(
    run_id: int,
    *,
    records_seen: int,
    domains_created: int,
    errors: int,
) -> None:
    with connection() as db:
        db.execute(
            """
            UPDATE ingestion_runs
            SET
                completed_at = ?,
                records_seen = ?,
                domains_created = ?,
                errors = ?,
                status = ?
            WHERE id = ?
            """,
            (
                utc_now(),
                records_seen,
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


def enrich_from_wikidata(
    *,
    limit: int | None = None,
    pause_seconds: float = 0.25,
) -> dict[str, Any]:
    links = registry_wikidata_links(
        limit=limit
    )

    run_id = begin_ingestion_run()

    entities_seen = 0
    websites_seen = 0
    domains_added = 0
    aliases_added = 0
    errors = 0

    qid_to_links: dict[
        str,
        list[dict[str, Any]],
    ] = {}

    for link in links:
        qid_to_links.setdefault(
            link[
                "qid"
            ],
            [],
        ).append(
            link
        )

    qids = list(
        qid_to_links
    )

    for batch in chunks(
        qids,
        BATCH_SIZE,
    ):
        try:
            entities = fetch_entities(
                batch
            )

        except Exception as error:
            errors += len(
                batch
            )

            print(
                "Wikidata batch error:",
                error,
            )

            time.sleep(
                2
            )

            continue

        for qid in batch:
            wikidata_entity = entities.get(
                qid,
                {},
            )

            if not isinstance(
                wikidata_entity,
                dict,
            ):
                continue

            entities_seen += 1

            websites = official_websites(
                wikidata_entity
            )

            aliases = english_aliases(
                wikidata_entity
            )

            for registry_link in qid_to_links.get(
                qid,
                [],
            ):
                entity_id = registry_link[
                    "entity_id"
                ]

                for alias in aliases:
                    add_alias(
                        entity_id=entity_id,
                        alias=alias,
                    )

                    aliases_added += 1

                for website in websites:
                    websites_seen += 1

                    try:
                        added = add_wikidata_domain(
                            entity_id=entity_id,
                            qid=qid,
                            website_url=website,
                        )

                        if added:
                            domains_added += 1

                    except Exception as error:
                        errors += 1

                        print(
                            "Domain enrichment error:",
                            qid,
                            website,
                            error,
                        )

        time.sleep(
            pause_seconds
        )

    finish_ingestion_run(
        run_id,
        records_seen=entities_seen,
        domains_created=domains_added,
        errors=errors,
    )

    return {
        "source": "wikidata_p856",
        "registry_links": len(
            links
        ),
        "unique_qids": len(
            qids
        ),
        "entities_seen": entities_seen,
        "official_websites_seen": (
            websites_seen
        ),
        "domains_processed": (
            domains_added
        ),
        "aliases_processed": (
            aliases_added
        ),
        "errors": errors,
    }


if __name__ == "__main__":
    from pprint import pprint

    pprint(
        enrich_from_wikidata(),
        sort_dicts=False,
    )
