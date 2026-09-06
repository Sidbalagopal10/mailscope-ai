from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DATABASE = Path(
    "data/rdap_intelligence/rdap_cache.db"
)


SCHEMA = """
CREATE TABLE IF NOT EXISTS rdap_cache (
    domain TEXT PRIMARY KEY,

    status TEXT NOT NULL,

    rdap_server TEXT,

    registration_date TEXT,
    expiration_date TEXT,
    last_changed_date TEXT,

    registrar_name TEXT,

    domain_age_days INTEGER,

    fetched_at TEXT NOT NULL,

    http_status INTEGER,

    response_json TEXT,

    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_rdap_age
ON rdap_cache(domain_age_days);

CREATE INDEX IF NOT EXISTS idx_rdap_status
ON rdap_cache(status);
"""


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def initialize() -> None:
    DATABASE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with sqlite3.connect(
        DATABASE
    ) as db:
        db.executescript(
            SCHEMA
        )
        db.commit()


def get_cached(
    domain: str,
) -> dict[str, Any] | None:
    initialize()

    with sqlite3.connect(
        DATABASE
    ) as db:
        db.row_factory = sqlite3.Row

        row = db.execute(
            """
            SELECT *
            FROM rdap_cache
            WHERE domain = ?
            """,
            (
                domain,
            ),
        ).fetchone()

    if row is None:
        return None

    result = dict(
        row
    )

    raw_json = result.get(
        "response_json"
    )

    if raw_json:
        try:
            result[
                "response_json"
            ] = json.loads(
                raw_json
            )
        except json.JSONDecodeError:
            pass

    return result


def save_cached(
    record: dict[str, Any],
) -> None:
    initialize()

    raw_json = record.get(
        "response_json"
    )

    if isinstance(
        raw_json,
        (
            dict,
            list,
        ),
    ):
        raw_json = json.dumps(
            raw_json,
            sort_keys=True,
        )

    with sqlite3.connect(
        DATABASE
    ) as db:
        db.execute(
            """
            INSERT INTO rdap_cache (
                domain,
                status,
                rdap_server,
                registration_date,
                expiration_date,
                last_changed_date,
                registrar_name,
                domain_age_days,
                fetched_at,
                http_status,
                response_json,
                error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

            ON CONFLICT(domain)
            DO UPDATE SET
                status = excluded.status,
                rdap_server = excluded.rdap_server,
                registration_date = excluded.registration_date,
                expiration_date = excluded.expiration_date,
                last_changed_date = excluded.last_changed_date,
                registrar_name = excluded.registrar_name,
                domain_age_days = excluded.domain_age_days,
                fetched_at = excluded.fetched_at,
                http_status = excluded.http_status,
                response_json = excluded.response_json,
                error = excluded.error
            """,
            (
                record[
                    "domain"
                ],
                record[
                    "status"
                ],
                record.get(
                    "rdap_server"
                ),
                record.get(
                    "registration_date"
                ),
                record.get(
                    "expiration_date"
                ),
                record.get(
                    "last_changed_date"
                ),
                record.get(
                    "registrar_name"
                ),
                record.get(
                    "domain_age_days"
                ),
                record.get(
                    "fetched_at"
                )
                or utc_now(),
                record.get(
                    "http_status"
                ),
                raw_json,
                record.get(
                    "error"
                ),
            ),
        )

        db.commit()
