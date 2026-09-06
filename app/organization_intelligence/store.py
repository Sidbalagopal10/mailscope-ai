from __future__ import annotations

import csv
import ipaddress
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DATABASE_PATH = Path(
    "data/organization_intelligence/"
    "organization_intelligence.db"
)

VALID_ENTITY_TYPES = {
    "bank",
    "business",
    "corporation",
    "defense",
    "government",
    "hospital",
    "nonprofit",
    "school",
    "startup",
    "technology",
    "university",
    "unknown",
}

VALID_IDENTITY_STATES = {
    "VERIFIED_ESTABLISHED",
    "VERIFIED_NEW",
    "PROVISIONAL",
    "OBSERVED_LEGITIMATE",
    "UNKNOWN",
    "SUSPICIOUS",
}

VALID_SECURITY_STATES = {
    "CLEAN",
    "NEUTRAL",
    "SUSPICIOUS",
    "KNOWN_MALICIOUS",
    "COMPROMISED_LEGITIMATE",
}


class OrganizationIntelligenceError(
    Exception
):
    pass


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def normalize_domain(
    domain: str,
) -> str:
    cleaned = str(
        domain or ""
    ).strip().lower()

    if not cleaned:
        raise OrganizationIntelligenceError(
            "A domain is required."
        )

    if "://" in cleaned:
        parsed = urlparse(
            cleaned
        )

        cleaned = (
            parsed.hostname
            or ""
        ).lower()

    cleaned = (
        cleaned.split("/")[0]
        .split(":")[0]
        .rstrip(".")
    )

    if cleaned.startswith(
        "www."
    ):
        cleaned = cleaned[4:]

    if (
        not cleaned
        or " " in cleaned
        or "@" in cleaned
        or "." not in cleaned
    ):
        raise OrganizationIntelligenceError(
            "Enter a complete hostname such as "
            "example.org."
        )

    try:
        ipaddress.ip_address(
            cleaned
        )

        raise OrganizationIntelligenceError(
            "Organization domains cannot be "
            "IP addresses."
        )

    except ValueError:
        pass

    return cleaned


def normalize_state(
    value: str,
    allowed: set[str],
    label: str,
) -> str:
    normalized = str(
        value or ""
    ).strip().upper()

    if normalized not in allowed:
        raise OrganizationIntelligenceError(
            f"Invalid {label}: {normalized}"
        )

    return normalized


def get_connection() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=30,
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA journal_mode=WAL"
    )

    connection.execute(
        "PRAGMA foreign_keys=ON"
    )

    return connection


def initialize_database() -> None:
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                legal_name TEXT NOT NULL,
                normalized_name TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                country_code TEXT,
                jurisdiction TEXT,
                registration_status TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS data_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_name TEXT NOT NULL UNIQUE,
                source_type TEXT NOT NULL,
                source_url TEXT,
                authoritative INTEGER NOT NULL DEFAULT 0,
                notes TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS organization_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                domain TEXT NOT NULL UNIQUE,
                identity_state TEXT NOT NULL,
                security_state TEXT NOT NULL,
                identity_confidence REAL NOT NULL,
                security_confidence REAL NOT NULL,
                domain_relationship TEXT NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (
                    organization_id
                )
                REFERENCES organizations(id)
                ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS source_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                domain_id INTEGER,
                source_id INTEGER NOT NULL,
                source_record_id TEXT,
                evidence_type TEXT NOT NULL,
                evidence_value TEXT,
                confidence REAL NOT NULL,
                observed_at TEXT NOT NULL,
                FOREIGN KEY (
                    organization_id
                )
                REFERENCES organizations(id)
                ON DELETE CASCADE,
                FOREIGN KEY (
                    domain_id
                )
                REFERENCES organization_domains(id)
                ON DELETE CASCADE,
                FOREIGN KEY (
                    source_id
                )
                REFERENCES data_sources(id)
                ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS
            idx_organizations_normalized_name
            ON organizations(normalized_name);

            CREATE INDEX IF NOT EXISTS
            idx_organization_domains_domain
            ON organization_domains(domain);

            CREATE INDEX IF NOT EXISTS
            idx_organization_domains_identity
            ON organization_domains(identity_state);

            CREATE INDEX IF NOT EXISTS
            idx_organization_domains_security
            ON organization_domains(security_state);
            """
        )

        connection.commit()


def normalize_name(
    name: str,
) -> str:
    return " ".join(
        str(
            name or ""
        ).strip().lower().split()
    )


def row_to_dict(
    row: sqlite3.Row,
) -> dict[str, Any]:
    return dict(
        row
    )


def upsert_source(
    *,
    source_name: str,
    source_type: str,
    source_url: str | None = None,
    authoritative: bool = False,
    notes: str | None = None,
) -> int:
    initialize_database()

    timestamp = utc_now()

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO data_sources (
                source_name,
                source_type,
                source_url,
                authoritative,
                notes,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_name)
            DO UPDATE SET
                source_type = excluded.source_type,
                source_url = excluded.source_url,
                authoritative = excluded.authoritative,
                notes = excluded.notes
            """,
            (
                source_name.strip(),
                source_type.strip(),
                source_url,
                int(
                    authoritative
                ),
                notes,
                timestamp,
            ),
        )

        row = connection.execute(
            """
            SELECT id
            FROM data_sources
            WHERE source_name = ?
            """,
            (
                source_name.strip(),
            ),
        ).fetchone()

        connection.commit()

    if row is None:
        raise OrganizationIntelligenceError(
            "Source could not be saved."
        )

    return int(
        row["id"]
    )


def upsert_organization_domain(
    *,
    legal_name: str,
    entity_type: str,
    domain: str,
    source_name: str,
    source_type: str,
    source_record_id: str | None = None,
    source_url: str | None = None,
    authoritative_source: bool = False,
    country_code: str | None = None,
    jurisdiction: str | None = None,
    registration_status: str | None = None,
    identity_state: str = "PROVISIONAL",
    security_state: str = "NEUTRAL",
    identity_confidence: float = 50.0,
    security_confidence: float = 25.0,
    domain_relationship: str = "reported",
    evidence_type: str = "registry_domain_association",
    evidence_value: str | None = None,
) -> dict[str, Any]:
    initialize_database()

    cleaned_name = str(
        legal_name or ""
    ).strip()

    if not cleaned_name:
        raise OrganizationIntelligenceError(
            "The legal organization name is required."
        )

    normalized_entity_type = str(
        entity_type or "unknown"
    ).strip().lower()

    if (
        normalized_entity_type
        not in VALID_ENTITY_TYPES
    ):
        normalized_entity_type = "unknown"

    cleaned_domain = normalize_domain(
        domain
    )

    identity_state = normalize_state(
        identity_state,
        VALID_IDENTITY_STATES,
        "identity state",
    )

    security_state = normalize_state(
        security_state,
        VALID_SECURITY_STATES,
        "security state",
    )

    identity_confidence = max(
        0.0,
        min(
            float(
                identity_confidence
            ),
            100.0,
        ),
    )

    security_confidence = max(
        0.0,
        min(
            float(
                security_confidence
            ),
            100.0,
        ),
    )

    source_id = upsert_source(
        source_name=source_name,
        source_type=source_type,
        source_url=source_url,
        authoritative=authoritative_source,
    )

    timestamp = utc_now()

    with get_connection() as connection:
        organization = connection.execute(
            """
            SELECT *
            FROM organizations
            WHERE normalized_name = ?
              AND COALESCE(country_code, '')
                  = COALESCE(?, '')
            """,
            (
                normalize_name(
                    cleaned_name
                ),
                country_code,
            ),
        ).fetchone()

        if organization is None:
            cursor = connection.execute(
                """
                INSERT INTO organizations (
                    legal_name,
                    normalized_name,
                    entity_type,
                    country_code,
                    jurisdiction,
                    registration_status,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cleaned_name,
                    normalize_name(
                        cleaned_name
                    ),
                    normalized_entity_type,
                    country_code,
                    jurisdiction,
                    registration_status,
                    timestamp,
                    timestamp,
                ),
            )

            organization_id = int(
                cursor.lastrowid
            )

        else:
            organization_id = int(
                organization["id"]
            )

            connection.execute(
                """
                UPDATE organizations
                SET
                    legal_name = ?,
                    entity_type = ?,
                    jurisdiction = COALESCE(?, jurisdiction),
                    registration_status = COALESCE(
                        ?,
                        registration_status
                    ),
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    cleaned_name,
                    normalized_entity_type,
                    jurisdiction,
                    registration_status,
                    timestamp,
                    organization_id,
                ),
            )

        connection.execute(
            """
            INSERT INTO organization_domains (
                organization_id,
                domain,
                identity_state,
                security_state,
                identity_confidence,
                security_confidence,
                domain_relationship,
                first_seen,
                last_seen,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain)
            DO UPDATE SET
                organization_id = excluded.organization_id,
                identity_state = excluded.identity_state,
                security_state = excluded.security_state,
                identity_confidence = MAX(
                    organization_domains.identity_confidence,
                    excluded.identity_confidence
                ),
                security_confidence = MAX(
                    organization_domains.security_confidence,
                    excluded.security_confidence
                ),
                domain_relationship = excluded.domain_relationship,
                last_seen = excluded.last_seen,
                updated_at = excluded.updated_at
            """,
            (
                organization_id,
                cleaned_domain,
                identity_state,
                security_state,
                identity_confidence,
                security_confidence,
                domain_relationship,
                timestamp,
                timestamp,
                timestamp,
                timestamp,
            ),
        )

        domain_row = connection.execute(
            """
            SELECT id
            FROM organization_domains
            WHERE domain = ?
            """,
            (
                cleaned_domain,
            ),
        ).fetchone()

        if domain_row is None:
            raise OrganizationIntelligenceError(
                "Domain record could not be saved."
            )

        domain_id = int(
            domain_row["id"]
        )

        connection.execute(
            """
            INSERT INTO source_evidence (
                organization_id,
                domain_id,
                source_id,
                source_record_id,
                evidence_type,
                evidence_value,
                confidence,
                observed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                organization_id,
                domain_id,
                source_id,
                source_record_id,
                evidence_type,
                evidence_value
                or cleaned_domain,
                identity_confidence,
                timestamp,
            ),
        )

        connection.commit()

    result = resolve_domain(
        cleaned_domain
    )

    if result is None:
        raise OrganizationIntelligenceError(
            "Saved record could not be resolved."
        )

    return result


def resolve_domain(
    hostname: str,
) -> dict[str, Any] | None:
    initialize_database()

    normalized = normalize_domain(
        hostname
    )

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                od.*,
                o.legal_name,
                o.entity_type,
                o.country_code,
                o.jurisdiction,
                o.registration_status
            FROM organization_domains od
            JOIN organizations o
              ON o.id = od.organization_id
            """
        ).fetchall()

        matches = [
            row
            for row in rows
            if (
                normalized
                == row["domain"]
                or normalized.endswith(
                    f".{row['domain']}"
                )
            )
        ]

        if not matches:
            return None

        matches.sort(
            key=lambda row: len(
                row["domain"]
            ),
            reverse=True,
        )

        selected = matches[0]

        evidence_rows = connection.execute(
            """
            SELECT
                se.*,
                ds.source_name,
                ds.source_type,
                ds.source_url,
                ds.authoritative
            FROM source_evidence se
            JOIN data_sources ds
              ON ds.id = se.source_id
            WHERE se.domain_id = ?
            ORDER BY
                ds.authoritative DESC,
                se.confidence DESC,
                se.observed_at DESC
            """,
            (
                selected["id"],
            ),
        ).fetchall()

    result = row_to_dict(
        selected
    )

    result["evidence"] = [
        row_to_dict(
            row
        )
        for row in evidence_rows
    ]

    result["matched_hostname"] = normalized

    return result


def list_domains(
    limit: int = 1000,
) -> list[dict[str, Any]]:
    initialize_database()

    safe_limit = max(
        1,
        min(
            int(limit),
            10000,
        ),
    )

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                od.*,
                o.legal_name,
                o.entity_type,
                o.country_code,
                o.jurisdiction,
                o.registration_status
            FROM organization_domains od
            JOIN organizations o
              ON o.id = od.organization_id
            ORDER BY
                od.identity_confidence DESC,
                o.legal_name ASC
            LIMIT ?
            """,
            (
                safe_limit,
            ),
        ).fetchall()

    return [
        row_to_dict(
            row
        )
        for row in rows
    ]


def get_summary() -> dict[str, Any]:
    initialize_database()

    with get_connection() as connection:
        organization_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM organizations
            """
        ).fetchone()["count"]

        domain_count = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM organization_domains
            """
        ).fetchone()["count"]

        authoritative_evidence = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM source_evidence se
            JOIN data_sources ds
              ON ds.id = se.source_id
            WHERE ds.authoritative = 1
            """
        ).fetchone()["count"]

        state_rows = connection.execute(
            """
            SELECT
                identity_state,
                COUNT(*) AS count
            FROM organization_domains
            GROUP BY identity_state
            """
        ).fetchall()

    return {
        "organizations": int(
            organization_count
        ),
        "domains": int(
            domain_count
        ),
        "authoritative_evidence_records": int(
            authoritative_evidence
        ),
        "identity_states": {
            row["identity_state"]: int(
                row["count"]
            )
            for row in state_rows
        },
    }


def import_csv_file(
    csv_path: Path,
) -> dict[str, Any]:
    if not csv_path.exists():
        raise OrganizationIntelligenceError(
            f"CSV file not found: {csv_path}"
        )

    required_columns = {
        "legal_name",
        "entity_type",
        "domain",
        "source_name",
        "source_type",
    }

    imported = 0
    failed = 0
    errors = []

    with csv_path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file_handle:
        reader = csv.DictReader(
            file_handle
        )

        available_columns = set(
            reader.fieldnames
            or []
        )

        missing = (
            required_columns
            - available_columns
        )

        if missing:
            raise OrganizationIntelligenceError(
                "CSV is missing required columns: "
                f"{sorted(missing)}"
            )

        for row_number, row in enumerate(
            reader,
            start=2,
        ):
            try:
                upsert_organization_domain(
                    legal_name=row[
                        "legal_name"
                    ],
                    entity_type=row[
                        "entity_type"
                    ],
                    domain=row[
                        "domain"
                    ],
                    source_name=row[
                        "source_name"
                    ],
                    source_type=row[
                        "source_type"
                    ],
                    source_record_id=(
                        row.get(
                            "source_record_id"
                        )
                        or None
                    ),
                    source_url=(
                        row.get(
                            "source_url"
                        )
                        or None
                    ),
                    authoritative_source=(
                        str(
                            row.get(
                                "authoritative_source",
                                "",
                            )
                        ).strip().lower()
                        in {
                            "1",
                            "true",
                            "yes",
                        }
                    ),
                    country_code=(
                        row.get(
                            "country_code"
                        )
                        or None
                    ),
                    jurisdiction=(
                        row.get(
                            "jurisdiction"
                        )
                        or None
                    ),
                    registration_status=(
                        row.get(
                            "registration_status"
                        )
                        or None
                    ),
                    identity_state=(
                        row.get(
                            "identity_state"
                        )
                        or "PROVISIONAL"
                    ),
                    security_state=(
                        row.get(
                            "security_state"
                        )
                        or "NEUTRAL"
                    ),
                    identity_confidence=float(
                        row.get(
                            "identity_confidence"
                        )
                        or 50
                    ),
                    security_confidence=float(
                        row.get(
                            "security_confidence"
                        )
                        or 25
                    ),
                    domain_relationship=(
                        row.get(
                            "domain_relationship"
                        )
                        or "reported"
                    ),
                    evidence_type=(
                        row.get(
                            "evidence_type"
                        )
                        or (
                            "registry_domain_"
                            "association"
                        )
                    ),
                    evidence_value=(
                        row.get(
                            "evidence_value"
                        )
                        or None
                    ),
                )

                imported += 1

            except Exception as error:
                failed += 1

                errors.append(
                    {
                        "row": row_number,
                        "error": str(
                            error
                        ),
                    }
                )

    return {
        "file": str(
            csv_path
        ),
        "imported": imported,
        "failed": failed,
        "errors": errors[:100],
    }
