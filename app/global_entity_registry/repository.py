from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.global_entity_registry.database import (
    connection,
)
from app.global_entity_registry.domain_utils import (
    normalize_hostname,
)
from app.global_entity_registry.ingestion.record_semantics import (
    evidence_for_identity_domain,
    identity_domains_for_record,
)
from app.global_entity_registry.ingestion.website_relationship_store import (
    upsert_website_relationships,
)
from app.global_entity_registry.models import (
    EntityRecord,
    SourceEvidence,
)


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def upsert_entity(
    record: EntityRecord,
) -> int:
    now = utc_now()

    with connection() as db:
        existing = db.execute(
            """
            SELECT id
            FROM entities
            WHERE canonical_name = ?
              AND COALESCE(country_code, '') =
                  COALESCE(?, '')
            """,
            (
                record.canonical_name,
                record.country_code,
            ),
        ).fetchone()

        if existing:
            entity_id = int(
                existing["id"]
            )

            db.execute(
                """
                UPDATE entities
                SET
                    entity_type =
                        COALESCE(?, entity_type),
                    country_name =
                        COALESCE(?, country_name),
                    continent =
                        COALESCE(?, continent),
                    status = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    record.entity_type,
                    record.country_name,
                    record.continent,
                    record.status,
                    now,
                    entity_id,
                ),
            )

        else:
            cursor = db.execute(
                """
                INSERT INTO entities (
                    canonical_name,
                    entity_type,
                    country_code,
                    country_name,
                    continent,
                    status,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.canonical_name,
                    record.entity_type,
                    record.country_code,
                    record.country_name,
                    record.continent,
                    record.status,
                    now,
                    now,
                ),
            )

            entity_id = int(
                cursor.lastrowid
            )

        for alias in record.aliases:
            cleaned = str(
                alias
            ).strip()

            if not cleaned:
                continue

            db.execute(
                """
                INSERT OR IGNORE INTO entity_aliases (
                    entity_id,
                    alias,
                    language_code,
                    source_name
                )
                VALUES (?, ?, NULL, ?)
                """,
                (
                    entity_id,
                    cleaned,
                    "combined_registry",
                ),
            )

        for identifier_type, identifier in (
            record.external_ids.items()
        ):
            if not identifier:
                continue

            db.execute(
                """
                INSERT OR IGNORE INTO external_identifiers (
                    entity_id,
                    identifier_type,
                    identifier_value,
                    source_name
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    entity_id,
                    identifier_type,
                    identifier,
                    identifier_type,
                ),
            )

        upsert_website_relationships(
            entity_id=entity_id,
            relationships=getattr(
                record,
                "website_relationships",
                [],
            ),
            observed_at=now,
            db=db,
        )

        for raw_domain in identity_domains_for_record(
            record
        ):
            domain = normalize_hostname(
                raw_domain
            )

            if not domain:
                continue

            existing_domain = db.execute(
                """
                SELECT id
                FROM domains
                WHERE entity_id = ?
                  AND domain = ?
                """,
                (
                    entity_id,
                    domain,
                ),
            ).fetchone()

            evidence_items = (
                evidence_for_identity_domain(
                    record,
                    domain,
                )
            )

            confidence = max(
                (
                    float(
                        item.confidence
                    )
                    for item in evidence_items
                ),
                default=0.50,
            )

            if existing_domain:
                domain_id = int(
                    existing_domain["id"]
                )

                db.execute(
                    """
                    UPDATE domains
                    SET
                        confidence =
                            MAX(confidence, ?),
                        last_verified_at = ?,
                        active = 1
                    WHERE id = ?
                    """,
                    (
                        confidence,
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
                        ?, ?, ?, 'official',
                        'source_verified',
                        ?, ?, ?, 1
                    )
                    """,
                    (
                        entity_id,
                        domain,
                        domain,
                        confidence,
                        now,
                        now,
                    ),
                )

                domain_id = int(
                    cursor.lastrowid
                )

            for item in evidence_items:
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
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        domain_id,
                        item.source_name,
                        item.source_record_id,
                        item.source_url,
                        item.evidence_type,
                        float(
                            item.confidence
                        ),
                        int(
                            item.authoritative
                        ),
                        now,
                        item.raw_reference,
                    ),
                )

        db.commit()

        return entity_id


def lookup_domain(
    value: str,
) -> dict[str, Any]:
    hostname = normalize_hostname(
        value
    )

    if not hostname:
        return {
            "matched": False,
            "hostname": "",
            "identity_state": "unknown",
        }

    with connection() as db:
        rows = db.execute(
            """
            SELECT
                d.domain,
                d.confidence,
                d.verification_state,

                e.id AS entity_id,
                e.canonical_name,
                e.entity_type,
                e.country_code,
                e.country_name,
                e.continent

            FROM domains d

            JOIN entities e
              ON e.id = d.entity_id

            WHERE d.active = 1
            """
        ).fetchall()

        matches = []

        for row in rows:
            official = str(
                row["domain"]
            )

            if (
                hostname == official
                or hostname.endswith(
                    "." + official
                )
            ):
                matches.append(
                    dict(
                        row
                    )
                )

        if not matches:
            return {
                "matched": False,
                "hostname": hostname,
                "identity_state": "unknown",
                "security_effect": "neutral",
            }

        matches.sort(
            key=lambda item: (
                len(
                    item["domain"]
                ),
                float(
                    item["confidence"]
                ),
            ),
            reverse=True,
        )

        best = matches[0]

        return {
            "matched": True,
            "hostname": hostname,
            "identity_state": "verified_official",
            "security_effect": (
                "identity_evidence_only"
            ),
            "entity": {
                "id": best[
                    "entity_id"
                ],
                "name": best[
                    "canonical_name"
                ],
                "type": best[
                    "entity_type"
                ],
                "country_code": best[
                    "country_code"
                ],
                "country_name": best[
                    "country_name"
                ],
                "continent": best[
                    "continent"
                ],
            },
            "official_domain": best[
                "domain"
            ],
            "confidence": float(
                best[
                    "confidence"
                ]
            ),
            "verification_state": (
                best[
                    "verification_state"
                ]
            ),
        }


def registry_summary() -> dict[str, Any]:
    with connection() as db:
        entity_count = db.execute(
            "SELECT COUNT(*) FROM entities"
        ).fetchone()[0]

        domain_count = db.execute(
            "SELECT COUNT(*) FROM domains"
        ).fetchone()[0]

        source_count = db.execute(
            """
            SELECT COUNT(DISTINCT source_name)
            FROM evidence_sources
            """
        ).fetchone()[0]

        countries = db.execute(
            """
            SELECT COUNT(DISTINCT country_code)
            FROM entities
            WHERE country_code IS NOT NULL
            """
        ).fetchone()[0]

        continents = db.execute(
            """
            SELECT COUNT(DISTINCT continent)
            FROM entities
            WHERE continent IS NOT NULL
            """
        ).fetchone()[0]

        types = db.execute(
            """
            SELECT
                COALESCE(entity_type, 'unknown')
                    AS entity_type,
                COUNT(*) AS count
            FROM entities
            GROUP BY entity_type
            ORDER BY count DESC
            """
        ).fetchall()

        return {
            "entities": int(
                entity_count
            ),
            "domains": int(
                domain_count
            ),
            "sources": int(
                source_count
            ),
            "countries": int(
                countries
            ),
            "continents": int(
                continents
            ),
            "entity_types": [
                dict(
                    row
                )
                for row in types
            ],
        }
