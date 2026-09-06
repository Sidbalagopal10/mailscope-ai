from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from app.benchmarking.urlhaus_loader import (
    download_urlhaus,
    parse_urlhaus_csv,
)


DATABASE = Path(
    "data/benchmarking/malicious/"
    "urlhaus_index.db"
)


SCHEMA = """
CREATE TABLE IF NOT EXISTS urlhaus_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    normalized_url TEXT NOT NULL UNIQUE,

    url_sha256 TEXT NOT NULL UNIQUE,

    hostname TEXT,

    source TEXT NOT NULL
        DEFAULT 'urlhaus'
);

CREATE INDEX IF NOT EXISTS idx_urlhaus_hostname
ON urlhaus_urls(hostname);

CREATE INDEX IF NOT EXISTS idx_urlhaus_hash
ON urlhaus_urls(url_sha256);
"""


def normalize_url(
    value: str,
) -> str:
    cleaned = str(
        value or ""
    ).strip()

    if not cleaned:
        return ""

    try:
        parsed = urlsplit(
            cleaned
        )

    except ValueError:
        return ""

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        return ""

    hostname = (
        parsed.hostname
        or ""
    ).lower().rstrip(".")

    if not hostname:
        return ""

    netloc = hostname

    if parsed.port:
        default_port = (
            parsed.scheme.lower()
            == "http"
            and parsed.port == 80
        ) or (
            parsed.scheme.lower()
            == "https"
            and parsed.port == 443
        )

        if not default_port:
            netloc = (
                f"{hostname}:{parsed.port}"
            )

    path = (
        parsed.path
        or "/"
    )

    return urlunsplit(
        (
            parsed.scheme.lower(),
            netloc,
            path,
            parsed.query,
            "",
        )
    )


def sha256_text(
    value: str,
) -> str:
    return hashlib.sha256(
        value.encode(
            "utf-8"
        )
    ).hexdigest()


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


def rebuild_index() -> dict[str, Any]:
    initialize()

    csv_path = download_urlhaus()

    cases = parse_urlhaus_csv(
        csv_path,
        limit=1_000_000,
    )

    inserted = 0
    skipped = 0

    with sqlite3.connect(
        DATABASE
    ) as db:
        db.execute(
            "DELETE FROM urlhaus_urls"
        )

        for case in cases:
            normalized = normalize_url(
                case.value
            )

            if not normalized:
                skipped += 1
                continue

            hostname = (
                urlsplit(
                    normalized
                ).hostname
                or ""
            )

            cursor = db.execute(
                """
                INSERT OR IGNORE INTO urlhaus_urls (
                    normalized_url,
                    url_sha256,
                    hostname,
                    source
                )
                VALUES (?, ?, ?, 'urlhaus')
                """,
                (
                    normalized,
                    sha256_text(
                        normalized
                    ),
                    hostname,
                ),
            )

            if cursor.rowcount:
                inserted += 1

        db.commit()

    return {
        "inserted": inserted,
        "skipped": skipped,
        "database": str(
            DATABASE
        ),
    }


def exact_lookup(
    value: str,
) -> dict[str, Any]:
    normalized = normalize_url(
        value
    )

    if not normalized:
        return {
            "matched": False,
            "match_type": "none",
            "normalized_url": "",
        }

    initialize()

    digest = sha256_text(
        normalized
    )

    with sqlite3.connect(
        DATABASE
    ) as db:
        db.row_factory = sqlite3.Row

        row = db.execute(
            """
            SELECT
                normalized_url,
                hostname,
                source

            FROM urlhaus_urls

            WHERE url_sha256 = ?

            LIMIT 1
            """,
            (
                digest,
            ),
        ).fetchone()

    if row is None:
        return {
            "matched": False,
            "match_type": "none",
            "normalized_url": normalized,
        }

    return {
        "matched": True,
        "match_type": "exact_url",
        "normalized_url": (
            row[
                "normalized_url"
            ]
        ),
        "hostname": row[
            "hostname"
        ],
        "source": row[
            "source"
        ],
    }


if __name__ == "__main__":
    print(
        rebuild_index()
    )
