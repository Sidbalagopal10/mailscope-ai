from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DATABASE_PATH = Path(
    "data/domain_trust.db"
)

VALID_STATUSES = {
    "TRUSTED",
    "UNKNOWN",
    "BLOCKED",
}


class DomainTrustError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def normalize_domain(
    domain: str,
) -> str:
    normalized = str(
        domain or ""
    ).strip().lower().rstrip(".")

    if normalized.startswith(
        "www."
    ):
        normalized = normalized[4:]

    if not normalized:
        raise DomainTrustError(
            "A domain is required."
        )

    if (
        "/" in normalized
        or "://" in normalized
        or "@" in normalized
        or " " in normalized
    ):
        raise DomainTrustError(
            "Enter only a domain, such as example.com."
        )

    if "." not in normalized:
        raise DomainTrustError(
            "Enter a complete domain such as example.com."
        )

    return normalized


def normalize_status(
    status: str,
) -> str:
    normalized = str(
        status or ""
    ).strip().upper()

    if normalized not in VALID_STATUSES:
        raise DomainTrustError(
            "Status must be TRUSTED, UNKNOWN, or BLOCKED."
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

    return connection


def initialize_database() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS domain_trust (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                category TEXT,
                notes TEXT,
                source TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_domain_trust_status
            ON domain_trust(status)
            """
        )

        connection.commit()


def row_to_dict(
    row: sqlite3.Row,
) -> dict[str, Any]:
    return dict(row)


def upsert_domain(
    *,
    domain: str,
    status: str,
    category: str | None = None,
    notes: str | None = None,
    source: str = "user",
) -> dict[str, Any]:
    initialize_database()

    normalized_domain = normalize_domain(
        domain
    )

    normalized_status = normalize_status(
        status
    )

    timestamp = utc_now()

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO domain_trust (
                domain,
                status,
                category,
                notes,
                source,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain)
            DO UPDATE SET
                status = excluded.status,
                category = excluded.category,
                notes = excluded.notes,
                source = excluded.source,
                updated_at = excluded.updated_at
            """,
            (
                normalized_domain,
                normalized_status,
                (category or "").strip() or None,
                (notes or "").strip() or None,
                source,
                timestamp,
                timestamp,
            ),
        )

        connection.commit()

        row = connection.execute(
            """
            SELECT *
            FROM domain_trust
            WHERE domain = ?
            """,
            (
                normalized_domain,
            ),
        ).fetchone()

    if row is None:
        raise DomainTrustError(
            "The domain record could not be saved."
        )

    return row_to_dict(
        row
    )


def delete_domain(
    domain_id: int,
) -> bool:
    initialize_database()

    with get_connection() as connection:
        cursor = connection.execute(
            """
            DELETE FROM domain_trust
            WHERE id = ?
            """,
            (
                domain_id,
            ),
        )

        connection.commit()

    return cursor.rowcount > 0


def list_domains(
    status: str | None = None,
) -> list[dict[str, Any]]:
    initialize_database()

    with get_connection() as connection:
        if status:
            normalized_status = normalize_status(
                status
            )

            rows = connection.execute(
                """
                SELECT *
                FROM domain_trust
                WHERE status = ?
                ORDER BY domain ASC
                """,
                (
                    normalized_status,
                ),
            ).fetchall()

        else:
            rows = connection.execute(
                """
                SELECT *
                FROM domain_trust
                ORDER BY status ASC, domain ASC
                """
            ).fetchall()

    return [
        row_to_dict(
            row
        )
        for row in rows
    ]


def find_matching_domain(
    hostname: str,
) -> dict[str, Any] | None:
    initialize_database()

    normalized = str(
        hostname or ""
    ).strip().lower().rstrip(".")

    if not normalized:
        return None

    records = list_domains()

    matches = [
        record
        for record in records
        if (
            normalized
            == record["domain"]
            or normalized.endswith(
                f".{record['domain']}"
            )
        )
    ]

    if not matches:
        return None

    matches.sort(
        key=lambda record: len(
            record["domain"]
        ),
        reverse=True,
    )

    return matches[0]


def seed_recommended_domains() -> int:
    recommended = [
        ("google.com", "technology"),
        ("googleapis.com", "technology"),
        ("gmail.com", "technology"),
        ("apple.com", "technology"),
        ("icloud.com", "technology"),
        ("microsoft.com", "technology"),
        ("microsoftonline.com", "technology"),
        ("office.com", "technology"),
        ("linkedin.com", "jobs"),
        ("lnkd.in", "jobs"),
        ("indeed.com", "jobs"),
        ("workday.com", "jobs"),
        ("myworkdayjobs.com", "jobs"),
        ("greenhouse.io", "jobs"),
        ("lever.co", "jobs"),
        ("github.com", "technology"),
        ("gwu.edu", "university"),
        ("amazon.com", "commerce"),
        ("paypal.com", "financial"),
        ("bankofamerica.com", "financial"),
        ("chase.com", "financial"),
        ("capitalone.com", "financial"),
        ("wellsfargo.com", "financial"),
        ("americanexpress.com", "financial"),
        ("citi.com", "financial"),
        ("citibank.com", "financial"),
    ]

    count = 0

    for domain, category in recommended:
        upsert_domain(
            domain=domain,
            status="TRUSTED",
            category=category,
            notes=(
                "Recommended starter entry. "
                "Trust applies only when authentication "
                "and domain-alignment checks pass."
            ),
            source="recommended",
        )

        count += 1

    return count
