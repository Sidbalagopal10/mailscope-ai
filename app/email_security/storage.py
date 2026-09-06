from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DATABASE_PATH = Path(
    "data/email_risk.db"
)


def get_connection() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=30,
    )

    connection.row_factory = (
        sqlite3.Row
    )

    return connection


def initialize_database() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS email_risk_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                gmail_message_id TEXT NOT NULL UNIQUE,
                thread_id TEXT,
                subject TEXT,
                sender TEXT,
                email_date TEXT,
                body_length INTEGER NOT NULL DEFAULT 0,
                link_count INTEGER NOT NULL DEFAULT 0,
                suspicious_url_count INTEGER NOT NULL DEFAULT 0,
                phishing_url_count INTEGER NOT NULL DEFAULT 0,
                content_score REAL NOT NULL,
                highest_url_score REAL NOT NULL,
                combined_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                is_suspicious INTEGER NOT NULL,
                is_phishing INTEGER NOT NULL,
                recommendation TEXT,
                reasons_json TEXT,
                analysis_json TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_email_risk_level
            ON email_risk_results(risk_level)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_email_scanned_at
            ON email_risk_results(scanned_at)
            """
        )

        connection.commit()


def save_email_analysis(
    analysis: dict[str, Any],
) -> dict[str, Any]:
    initialize_database()

    timestamp = (
        datetime.now(timezone.utc)
        .isoformat()
    )

    gmail_message_id = str(
        analysis.get(
            "gmail_message_id",
            "",
        )
    ).strip()

    if not gmail_message_id:
        raise ValueError(
            "Gmail message ID is required."
        )

    reasons_json = json.dumps(
        analysis.get(
            "reasons",
            [],
        ),
        ensure_ascii=False,
        default=str,
    )

    analysis_json = json.dumps(
        analysis,
        ensure_ascii=False,
        default=str,
    )

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO email_risk_results (
                gmail_message_id,
                thread_id,
                subject,
                sender,
                email_date,
                body_length,
                link_count,
                suspicious_url_count,
                phishing_url_count,
                content_score,
                highest_url_score,
                combined_score,
                risk_level,
                is_suspicious,
                is_phishing,
                recommendation,
                reasons_json,
                analysis_json,
                scanned_at,
                updated_at
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            ON CONFLICT(gmail_message_id)
            DO UPDATE SET
                thread_id = excluded.thread_id,
                subject = excluded.subject,
                sender = excluded.sender,
                email_date = excluded.email_date,
                body_length = excluded.body_length,
                link_count = excluded.link_count,
                suspicious_url_count = excluded.suspicious_url_count,
                phishing_url_count = excluded.phishing_url_count,
                content_score = excluded.content_score,
                highest_url_score = excluded.highest_url_score,
                combined_score = excluded.combined_score,
                risk_level = excluded.risk_level,
                is_suspicious = excluded.is_suspicious,
                is_phishing = excluded.is_phishing,
                recommendation = excluded.recommendation,
                reasons_json = excluded.reasons_json,
                analysis_json = excluded.analysis_json,
                updated_at = excluded.updated_at
            """,
            (
                gmail_message_id,
                analysis.get(
                    "thread_id"
                ),
                analysis.get(
                    "subject"
                ),
                analysis.get(
                    "sender"
                ),
                analysis.get(
                    "date"
                ),
                int(
                    analysis.get(
                        "body_length",
                        0,
                    )
                ),
                int(
                    analysis.get(
                        "link_count",
                        0,
                    )
                ),
                int(
                    analysis.get(
                        "suspicious_url_count",
                        0,
                    )
                ),
                int(
                    analysis.get(
                        "phishing_url_count",
                        0,
                    )
                ),
                float(
                    analysis.get(
                        "content_score",
                        0,
                    )
                ),
                float(
                    analysis.get(
                        "highest_url_score",
                        0,
                    )
                ),
                float(
                    analysis.get(
                        "combined_score",
                        0,
                    )
                ),
                analysis.get(
                    "risk_level",
                    "LOW",
                ),
                int(
                    bool(
                        analysis.get(
                            "is_suspicious",
                            False,
                        )
                    )
                ),
                int(
                    bool(
                        analysis.get(
                            "is_phishing",
                            False,
                        )
                    )
                ),
                analysis.get(
                    "recommendation"
                ),
                reasons_json,
                analysis_json,
                timestamp,
                timestamp,
            ),
        )

        connection.commit()

    return get_email_analysis(
        gmail_message_id
    )


def row_to_dict(
    row: sqlite3.Row,
) -> dict[str, Any]:
    record = dict(row)

    record["is_suspicious"] = bool(
        record["is_suspicious"]
    )

    record["is_phishing"] = bool(
        record["is_phishing"]
    )

    try:
        record["reasons"] = json.loads(
            record.pop(
                "reasons_json",
                "[]",
            )
        )
    except json.JSONDecodeError:
        record["reasons"] = []

    try:
        record["analysis"] = json.loads(
            record.pop(
                "analysis_json",
                "{}",
            )
        )
    except json.JSONDecodeError:
        record["analysis"] = {}

    return record


def get_email_analysis(
    gmail_message_id: str,
) -> dict[str, Any] | None:
    initialize_database()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM email_risk_results
            WHERE gmail_message_id = ?
            """,
            (
                gmail_message_id,
            ),
        ).fetchone()

    if row is None:
        return None

    return row_to_dict(
        row
    )


def list_email_analyses(
    limit: int = 200,
) -> list[dict[str, Any]]:
    initialize_database()

    safe_limit = max(
        1,
        min(
            int(limit),
            1000,
        ),
    )

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM email_risk_results
            ORDER BY updated_at DESC
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
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS total_emails,
                SUM(is_suspicious) AS suspicious_emails,
                SUM(is_phishing) AS phishing_emails,
                AVG(combined_score) AS average_score,
                MAX(combined_score) AS highest_score,
                SUM(link_count) AS total_links,
                SUM(suspicious_url_count) AS suspicious_urls
            FROM email_risk_results
            """
        ).fetchone()

        risk_rows = connection.execute(
            """
            SELECT
                risk_level,
                COUNT(*) AS count
            FROM email_risk_results
            GROUP BY risk_level
            """
        ).fetchall()

    return {
        "total_emails": int(
            row["total_emails"]
            or 0
        ),
        "suspicious_emails": int(
            row["suspicious_emails"]
            or 0
        ),
        "phishing_emails": int(
            row["phishing_emails"]
            or 0
        ),
        "average_score": round(
            float(
                row["average_score"]
                or 0
            ),
            2,
        ),
        "highest_score": round(
            float(
                row["highest_score"]
                or 0
            ),
            2,
        ),
        "total_links": int(
            row["total_links"]
            or 0
        ),
        "suspicious_urls": int(
            row["suspicious_urls"]
            or 0
        ),
        "risk_distribution": {
            risk_row["risk_level"]: int(
                risk_row["count"]
            )
            for risk_row in risk_rows
        },
    }
