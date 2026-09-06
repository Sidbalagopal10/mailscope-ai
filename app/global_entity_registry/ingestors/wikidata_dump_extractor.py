from __future__ import annotations

import bz2
import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterator

import ijson

from app.global_entity_registry.domain_utils import (
    normalize_hostname,
)
from app.global_entity_registry.ingestion.relationship_builder import (
    build_website_relationship,
)
from app.global_entity_registry.models import (
    EntityRecord,
    SourceEvidence,
)
from app.global_entity_registry.public_suffix import (
    registrable_domain,
)
from app.global_entity_registry.repository import (
    upsert_entity,
)
from app.global_entity_registry.wikidata_categories import (
    classify_entity,
)


DEFAULT_CHECKPOINT_PATH = Path(
    "data/global_entity_registry/checkpoints/"
    "wikidata_dump_checkpoint.json"
)

DEFAULT_STATS_PATH = Path(
    "data/global_entity_registry/wikidata/"
    "latest_extraction_stats.json"
)


class WikidataDumpError(Exception):
    pass


def claim_strings(
    entity: dict[str, Any],
    property_id: str,
) -> list[str]:
    claims = (
        entity.get(
            "claims",
            {},
        )
        or {}
    )

    statements = claims.get(
        property_id,
        [],
    )

    values: list[str] = []

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


def english_label(
    entity: dict[str, Any],
) -> str:
    labels = (
        entity.get(
            "labels",
            {},
        )
        or {}
    )

    english = labels.get(
        "en"
    )

    if isinstance(
        english,
        dict,
    ):
        value = str(
            english.get(
                "value",
                "",
            )
        ).strip()

        if value:
            return value

    # Fallback: use any available label.
    for item in labels.values():
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
            return value

    return ""


def aliases(
    entity: dict[str, Any],
) -> list[str]:
    raw_aliases = (
        entity.get(
            "aliases",
            {},
        )
        or {}
    )

    values: list[str] = []

    # English first.
    languages = [
        "en",
        *[
            key
            for key in raw_aliases
            if key != "en"
        ],
    ]

    for language in languages:
        items = raw_aliases.get(
            language,
            [],
        )

        if not isinstance(
            items,
            list,
        ):
            continue

        for item in items:
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

            if (
                value
                and value
                not in values
            ):
                values.append(
                    value
                )

            # Bound alias explosion.
            if len(
                values
            ) >= 50:
                return values

    return values


def qid(
    entity: dict[str, Any],
) -> str:
    value = str(
        entity.get(
            "id",
            "",
        )
    ).strip()

    if value.startswith(
        "Q"
    ):
        return value

    return ""


def entity_to_record(
    entity: dict[str, Any],
) -> EntityRecord | None:
    websites = official_websites(
        entity
    )

    if not websites:
        return None

    canonical_name = english_label(
        entity
    )

    if not canonical_name:
        return None

    entity_qid = qid(
        entity
    )

    if not entity_qid:
        return None

    classification = classify_entity(
        entity
    )

    official_domains: list[str] = []

    website_relationships = []

    evidence: dict[
        str,
        list[SourceEvidence]
    ] = {}

    for website in websites:
        relationship = build_website_relationship(
            website,
            source_name="wikidata_dump_p856",
            source_record_id=entity_qid,
            confidence=0.82,
        )

        if not relationship.hostname:
            continue

        website_relationships.append(
            relationship
        )

        if not (
            relationship.eligible_for_domain_identity
        ):
            continue

        hostname = relationship.hostname

        if hostname not in official_domains:
            official_domains.append(
                hostname
            )

        evidence.setdefault(
            hostname,
            [],
        ).append(
            SourceEvidence(
                source_name=(
                    "wikidata_dump_p856"
                ),
                source_record_id=(
                    entity_qid
                ),
                source_url=(
                    "https://www.wikidata.org/"
                    f"wiki/{entity_qid}"
                ),
                evidence_type=(
                    "official_website"
                ),
                confidence=0.82,
                authoritative=False,
                raw_reference=website,
            )
        )

    if not official_domains:
        return None

    return EntityRecord(
        canonical_name=(
            canonical_name
        ),
        entity_type=(
            classification[
                "primary_category"
            ]
        ),
        country_code=None,
        country_name=None,
        continent=None,
        status="active",
        aliases=aliases(
            entity
        ),
        domains=official_domains,
        website_relationships=website_relationships,
        external_ids={
            "wikidata": entity_qid,
        },
        evidence=evidence,
    )


def iter_json_array_dump(
    path: Path,
) -> Iterator[dict[str, Any]]:
    """
    Stream Wikidata's JSON-array dump without loading it into RAM.

    Supports:
      *.json
      *.json.bz2
    """
    if not path.exists():
        raise WikidataDumpError(
            f"Dump does not exist: {path}"
        )

    if path.name.endswith(
        ".bz2"
    ):
        file_handle = bz2.open(
            path,
            "rb",
        )

    else:
        file_handle = path.open(
            "rb"
        )

    with file_handle:
        for item in ijson.items(
            file_handle,
            "item",
        ):
            if isinstance(
                item,
                dict,
            ):
                yield item


def load_checkpoint(
    path: Path = DEFAULT_CHECKPOINT_PATH,
) -> dict[str, Any]:
    if not path.exists():
        return {
            "entities_seen": 0,
            "last_qid": None,
        }

    try:
        return json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

    except (
        OSError,
        json.JSONDecodeError,
    ):
        return {
            "entities_seen": 0,
            "last_qid": None,
        }


def save_checkpoint(
    *,
    entities_seen: int,
    last_qid: str | None,
    stats: dict[str, Any],
    path: Path = DEFAULT_CHECKPOINT_PATH,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    payload = {
        "entities_seen": entities_seen,
        "last_qid": last_qid,
        "stats": stats,
        "updated_at_unix": (
            time.time()
        ),
    }

    path.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def extract_dump(
    dump_path: Path,
    *,
    limit: int | None = None,
    checkpoint_every: int = 10_000,
    resume: bool = False,
) -> dict[str, Any]:
    checkpoint = load_checkpoint()

    resume_after_qid = (
        checkpoint.get(
            "last_qid"
        )
        if resume
        else None
    )

    waiting_for_resume = bool(
        resume_after_qid
    )

    stats: dict[str, Any] = {
        "entities_seen": 0,
        "entities_with_p856": 0,
        "records_imported": 0,
        "records_skipped": 0,
        "errors": 0,
        "categories": {},
        "domains_seen": 0,
    }

    last_qid: str | None = None

    for entity in iter_json_array_dump(
        dump_path
    ):
        current_qid = qid(
            entity
        )

        if waiting_for_resume:
            if (
                current_qid
                == resume_after_qid
            ):
                waiting_for_resume = False

            continue

        stats[
            "entities_seen"
        ] += 1

        last_qid = (
            current_qid
            or last_qid
        )

        if official_websites(
            entity
        ):
            stats[
                "entities_with_p856"
            ] += 1

        try:
            record = entity_to_record(
                entity
            )

            if record is None:
                stats[
                    "records_skipped"
                ] += 1

            else:
                upsert_entity(
                    record
                )

                stats[
                    "records_imported"
                ] += 1

                stats[
                    "domains_seen"
                ] += len(
                    record.domains
                )

                category = (
                    record.entity_type
                    or "unclassified"
                )

                categories = stats[
                    "categories"
                ]

                categories[
                    category
                ] = (
                    categories.get(
                        category,
                        0,
                    )
                    + 1
                )

        except Exception as error:
            stats[
                "errors"
            ] += 1

            if (
                stats[
                    "errors"
                ]
                <= 20
            ):
                print(
                    "Extraction error:",
                    current_qid,
                    repr(
                        error
                    ),
                )

        if (
            checkpoint_every > 0
            and stats[
                "entities_seen"
            ]
            % checkpoint_every
            == 0
        ):
            save_checkpoint(
                entities_seen=(
                    stats[
                        "entities_seen"
                    ]
                ),
                last_qid=last_qid,
                stats=stats,
            )

            print(
                "Checkpoint:",
                stats[
                    "entities_seen"
                ],
                "entities |",
                stats[
                    "records_imported"
                ],
                "imported |",
                stats[
                    "domains_seen"
                ],
                "domains",
            )

        if (
            limit is not None
            and stats[
                "entities_seen"
            ]
            >= limit
        ):
            break

    save_checkpoint(
        entities_seen=(
            stats[
                "entities_seen"
            ]
        ),
        last_qid=last_qid,
        stats=stats,
    )

    DEFAULT_STATS_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    DEFAULT_STATS_PATH.write_text(
        json.dumps(
            stats,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    return stats
