from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


DATABASE_PATH = Path("data/monitor_state.db")


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
            CREATE TABLE IF NOT EXISTS processed_messages (
                gmail_message_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                risk_level TEXT,
                combined_score REAL,
                error_message TEXT,
                processed_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_processed_messages_status
            ON processed_messages(status)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_processed_messages_processed_at
            ON processed_messages(processed_at)
            """
        )

        connection.commit()


def message_was_processed(
    gmail_message_id: str,
) -> bool:
    initialize_database()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT 1
            FROM processed_messages
            WHERE gmail_message_id = ?
              AND status = 'completed'
            LIMIT 1
            """,
            (gmail_message_id,),
        ).fetchone()

    return row is not None


def save_processed_message(
    *,
    gmail_message_id: str,
    status: str,
    risk_level: Optional[str] = None,
    combined_score: Optional[float] = None,
    error_message: Optional[str] = None,
) -> None:
    initialize_database()

    timestamp = (
        datetime.now(timezone.utc)
        .isoformat()
    )

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO processed_messages (
                gmail_message_id,
                status,
                risk_level,
                combined_score,
                error_message,
                processed_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(gmail_message_id)
            DO UPDATE SET
                status = excluded.status,
                risk_level = excluded.risk_level,
                combined_score = excluded.combined_score,
                error_message = excluded.error_message,
                updated_at = excluded.updated_at
            """,
            (
                gmail_message_id,
                status,
                risk_level,
                combined_score,
                error_message,
                timestamp,
                timestamp,
            ),
        )

        connection.commit()


def get_monitor_summary() -> dict:
    initialize_database()

    with get_connection() as connection:
        summary = connection.execute(
            """
            SELECT
                COUNT(*) AS total_processed,
                SUM(
                    CASE
                        WHEN status = 'completed'
                        THEN 1
                        ELSE 0
                    END
                ) AS completed,
                SUM(
                    CASE
                        WHEN status = 'failed'
                        THEN 1
                        ELSE 0
                    END
                ) AS failed,
                MAX(updated_at) AS last_activity
            FROM processed_messages
            """
        ).fetchone()

        risk_rows = connection.execute(
            """
            SELECT
                risk_level,
                COUNT(*) AS count
            FROM processed_messages
            WHERE status = 'completed'
              AND risk_level IS NOT NULL
            GROUP BY risk_level
            """
        ).fetchall()

    return {
        "total_processed": int(
            summary["total_processed"] or 0
        ),
        "completed": int(
            summary["completed"] or 0
        ),
        "failed": int(
            summary["failed"] or 0
        ),
        "last_activity": summary["last_activity"],
        "risk_distribution": {
            row["risk_level"]: int(
                row["count"]
            )
            for row in risk_rows
        },
    }
