from __future__ import annotations

import json
import random
import time
from pathlib import Path
from typing import Any

import requests

from app.global_entity_registry.database import (
    connection,
)
from app.global_entity_registry.ingestors.wikidata_enricher import (
    add_alias,
    add_wikidata_domain,
    english_aliases,
    official_websites,
)


API = (
    "https://www.wikidata.org/w/api.php"
)

CACHE = Path(
    "data/rehearsal/"
    "targeted_wikidata_cache.json"
)


def target_links() -> dict[
    str,
    list[int],
]:
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

    result: dict[
        str,
        list[int],
    ] = {}

    for row in rows:
        qid = str(
            row[
                "identifier_value"
            ]
            or ""
        ).strip()

        if not qid:
            continue

        if not qid.startswith(
            "Q"
        ):
            qid = (
                "Q"
                + qid
            )

        result.setdefault(
            qid,
            [],
        ).append(
            int(
                row[
                    "entity_id"
                ]
            )
        )

    return result


def fetch_target_entities(
    qids: list[str],
    *,
    maximum_attempts: int = 6,
) -> dict[str, Any]:
    """
    Fetch only our small target set.

    One request is preferred. On throttling/server failure,
    use exponential backoff rather than repeatedly hammering
    Wikidata.
    """

    CACHE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if CACHE.exists():
        try:
            cached = json.loads(
                CACHE.read_text(
                    encoding="utf-8"
                )
            )

            cached_entities = cached.get(
                "entities",
                {}
            )

            if all(
                qid in cached_entities
                for qid in qids
            ):
                print(
                    "✅ Using complete local Wikidata target cache."
                )

                return cached_entities

        except Exception:
            pass

    params = {
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
    }

    headers = {
        "User-Agent": (
            "AI-Mail-Phishing-Detector/"
            "research-rehearsal"
        )
    }

    for attempt in range(
        1,
        maximum_attempts + 1,
    ):
        response = requests.get(
            API,
            params=params,
            headers=headers,
            timeout=60,
        )

        if response.status_code == 200:
            payload = response.json()

            CACHE.write_text(
                json.dumps(
                    payload,
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )

            return payload.get(
                "entities",
                {}
            )

        if response.status_code in {
            429,
            500,
            502,
            503,
            504,
        }:
            retry_after = (
                response.headers.get(
                    "Retry-After"
                )
            )

            if retry_after:
                try:
                    delay = float(
                        retry_after
                    )

                except ValueError:
                    delay = 0.0

            else:
                delay = 0.0

            if delay <= 0:
                delay = min(
                    60.0,
                    (
                        2 ** (
                            attempt
                            + 1
                        )
                    )
                    + random.uniform(
                        0.0,
                        2.0,
                    ),
                )

            print(
                f"Wikidata HTTP "
                f"{response.status_code}; "
                f"waiting {delay:.1f}s "
                f"(attempt {attempt}/"
                f"{maximum_attempts})"
            )

            time.sleep(
                delay
            )

            continue

        response.raise_for_status()

    raise RuntimeError(
        "Targeted Wikidata fetch failed "
        "after retry/backoff."
    )


def enrich_targets() -> dict[str, Any]:
    links = target_links()

    qids = sorted(
        links
    )

    entities = fetch_target_entities(
        qids
    )

    found = 0

    websites_seen = 0
    domains_added = 0

    aliases_seen = 0
    aliases_added = 0

    errors = 0

    for qid in qids:
        entity = entities.get(
            qid,
            {}
        )

        if not isinstance(
            entity,
            dict,
        ):
            continue

        if entity.get(
            "missing"
        ) is not None:
            continue

        found += 1

        aliases = english_aliases(
            entity
        )

        websites = official_websites(
            entity
        )

        for entity_id in links[
            qid
        ]:
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
                        qid,
                        repr(
                            error
                        ),
                    )

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
                        "Website error:",
                        qid,
                        website,
                        repr(
                            error
                        ),
                    )

    return {
        "targets": len(
            qids
        ),
        "targets_found": found,
        "websites_seen": websites_seen,
        "domains_processed": domains_added,
        "aliases_seen": aliases_seen,
        "aliases_processed": aliases_added,
        "errors": errors,
    }
