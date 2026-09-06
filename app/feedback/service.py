import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


DATABASE_PATH = Path("data/feedback.db")


class FeedbackError(Exception):
    """Raised when feedback cannot be saved or retrieved."""


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
        "PRAGMA foreign_keys = ON"
    )

    connection.execute(
        "PRAGMA journal_mode = WAL"
    )

    return connection


def initialize_feedback_database() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS url_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                predicted_label INTEGER NOT NULL
                    CHECK(predicted_label IN (0, 1)),
                predicted_probability REAL
                    CHECK(
                        predicted_probability IS NULL
                        OR (
                            predicted_probability >= 0
                            AND predicted_probability <= 1
                        )
                    ),
                final_score REAL
                    CHECK(
                        final_score IS NULL
                        OR (
                            final_score >= 0
                            AND final_score <= 100
                        )
                    ),
                risk_level TEXT,
                is_prediction_correct INTEGER NOT NULL
                    CHECK(is_prediction_correct IN (0, 1)),
                confirmed_label INTEGER NOT NULL
                    CHECK(confirmed_label IN (0, 1)),
                model_version TEXT,
                model_type TEXT,
                source TEXT NOT NULL DEFAULT 'dashboard',
                notes TEXT,
                analysis_snapshot TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_url_feedback_created_at
            ON url_feedback(created_at)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_url_feedback_confirmed_label
            ON url_feedback(confirmed_label)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_url_feedback_url
            ON url_feedback(url)
            """
        )

        connection.commit()


def serialize_snapshot(
    snapshot: Optional[Dict[str, Any]],
) -> Optional[str]:
    if snapshot is None:
        return None

    return json.dumps(
        snapshot,
        ensure_ascii=False,
        default=str,
    )


def deserialize_snapshot(
    value: Optional[str],
) -> Optional[Dict[str, Any]]:
    if not value:
        return None

    try:
        decoded = json.loads(value)

        if isinstance(decoded, dict):
            return decoded

        return {
            "value": decoded,
        }

    except json.JSONDecodeError:
        return {
            "raw_value": value,
        }


def save_feedback(
    *,
    url: str,
    predicted_label: int,
    is_prediction_correct: bool,
    confirmed_label: int,
    predicted_probability: Optional[float] = None,
    final_score: Optional[float] = None,
    risk_level: Optional[str] = None,
    model_version: Optional[str] = None,
    model_type: Optional[str] = None,
    source: str = "dashboard",
    notes: Optional[str] = None,
    analysis_snapshot: Optional[
        Dict[str, Any]
    ] = None,
) -> Dict[str, Any]:
    initialize_feedback_database()

    cleaned_url = url.strip()

    if not cleaned_url:
        raise FeedbackError(
            "URL cannot be empty."
        )

    if predicted_label not in {0, 1}:
        raise FeedbackError(
            "Predicted label must be 0 or 1."
        )

    if confirmed_label not in {0, 1}:
        raise FeedbackError(
            "Confirmed label must be 0 or 1."
        )

    expected_confirmed_label = (
        predicted_label
        if is_prediction_correct
        else 1 - predicted_label
    )

    if confirmed_label != expected_confirmed_label:
        raise FeedbackError(
            "Confirmed label is inconsistent with "
            "the correctness response."
        )

    if (
        predicted_probability is not None
        and not 0 <= predicted_probability <= 1
    ):
        raise FeedbackError(
            "Predicted probability must be "
            "between 0 and 1."
        )

    if (
        final_score is not None
        and not 0 <= final_score <= 100
    ):
        raise FeedbackError(
            "Final score must be between 0 and 100."
        )

    timestamp = (
        datetime.now(timezone.utc)
        .isoformat()
    )

    snapshot_json = serialize_snapshot(
        analysis_snapshot
    )

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO url_feedback (
                url,
                predicted_label,
                predicted_probability,
                final_score,
                risk_level,
                is_prediction_correct,
                confirmed_label,
                model_version,
                model_type,
                source,
                notes,
                analysis_snapshot,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cleaned_url,
                predicted_label,
                predicted_probability,
                final_score,
                risk_level,
                int(is_prediction_correct),
                confirmed_label,
                model_version,
                model_type,
                source.strip() or "dashboard",
                notes.strip() if notes else None,
                snapshot_json,
                timestamp,
                timestamp,
            ),
        )

        feedback_id = int(
            cursor.lastrowid
        )

        connection.commit()

    feedback = get_feedback_by_id(
        feedback_id
    )

    if feedback is None:
        raise FeedbackError(
            "Feedback was saved but could not "
            "be retrieved."
        )

    return feedback


def row_to_dictionary(
    row: sqlite3.Row,
) -> Dict[str, Any]:
    record = dict(row)

    record["is_prediction_correct"] = bool(
        record["is_prediction_correct"]
    )

    record["predicted_classification"] = (
        "phishing"
        if record["predicted_label"] == 1
        else "benign"
    )

    record["confirmed_classification"] = (
        "phishing"
        if record["confirmed_label"] == 1
        else "benign"
    )

    record["analysis_snapshot"] = (
        deserialize_snapshot(
            record.get(
                "analysis_snapshot"
            )
        )
    )

    return record


def get_feedback_by_id(
    feedback_id: int,
) -> Optional[Dict[str, Any]]:
    initialize_feedback_database()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM url_feedback
            WHERE id = ?
            """,
            (feedback_id,),
        ).fetchone()

    if row is None:
        return None

    return row_to_dictionary(row)


def list_feedback(
    *,
    limit: int = 100,
    offset: int = 0,
    confirmed_label: Optional[int] = None,
) -> List[Dict[str, Any]]:
    initialize_feedback_database()

    safe_limit = max(
        1,
        min(int(limit), 1000),
    )

    safe_offset = max(
        0,
        int(offset),
    )

    query = """
        SELECT *
        FROM url_feedback
    """

    parameters: List[Any] = []

    if confirmed_label is not None:
        if confirmed_label not in {0, 1}:
            raise FeedbackError(
                "Confirmed label must be 0 or 1."
            )

        query += """
            WHERE confirmed_label = ?
        """

        parameters.append(
            confirmed_label
        )

    query += """
        ORDER BY id DESC
        LIMIT ?
        OFFSET ?
    """

    parameters.extend(
        [
            safe_limit,
            safe_offset,
        ]
    )

    with get_connection() as connection:
        rows = connection.execute(
            query,
            parameters,
        ).fetchall()

    return [
        row_to_dictionary(row)
        for row in rows
    ]


def get_feedback_summary() -> Dict[str, Any]:
    initialize_feedback_database()

    with get_connection() as connection:
        summary = connection.execute(
            """
            SELECT
                COUNT(*) AS total_feedback,
                SUM(
                    CASE
                        WHEN is_prediction_correct = 1
                        THEN 1
                        ELSE 0
                    END
                ) AS correct_predictions,
                SUM(
                    CASE
                        WHEN is_prediction_correct = 0
                        THEN 1
                        ELSE 0
                    END
                ) AS incorrect_predictions,
                SUM(
                    CASE
                        WHEN confirmed_label = 1
                        THEN 1
                        ELSE 0
                    END
                ) AS confirmed_phishing,
                SUM(
                    CASE
                        WHEN confirmed_label = 0
                        THEN 1
                        ELSE 0
                    END
                ) AS confirmed_benign
            FROM url_feedback
            """
        ).fetchone()

        confusion = connection.execute(
            """
            SELECT
                SUM(
                    CASE
                        WHEN predicted_label = 0
                        AND confirmed_label = 0
                        THEN 1
                        ELSE 0
                    END
                ) AS true_negatives,
                SUM(
                    CASE
                        WHEN predicted_label = 1
                        AND confirmed_label = 0
                        THEN 1
                        ELSE 0
                    END
                ) AS false_positives,
                SUM(
                    CASE
                        WHEN predicted_label = 0
                        AND confirmed_label = 1
                        THEN 1
                        ELSE 0
                    END
                ) AS false_negatives,
                SUM(
                    CASE
                        WHEN predicted_label = 1
                        AND confirmed_label = 1
                        THEN 1
                        ELSE 0
                    END
                ) AS true_positives
            FROM url_feedback
            """
        ).fetchone()

    total = int(
        summary["total_feedback"] or 0
    )

    correct = int(
        summary["correct_predictions"] or 0
    )

    accuracy = (
        correct / total
        if total
        else 0.0
    )

    return {
        "total_feedback": total,
        "correct_predictions": correct,
        "incorrect_predictions": int(
            summary["incorrect_predictions"]
            or 0
        ),
        "confirmed_phishing": int(
            summary["confirmed_phishing"]
            or 0
        ),
        "confirmed_benign": int(
            summary["confirmed_benign"]
            or 0
        ),
        "verified_accuracy": round(
            accuracy,
            6,
        ),
        "confusion_matrix": {
            "true_negatives": int(
                confusion["true_negatives"]
                or 0
            ),
            "false_positives": int(
                confusion["false_positives"]
                or 0
            ),
            "false_negatives": int(
                confusion["false_negatives"]
                or 0
            ),
            "true_positives": int(
                confusion["true_positives"]
                or 0
            ),
        },
    }


def delete_feedback(
    feedback_id: int,
) -> bool:
    initialize_feedback_database()

    with get_connection() as connection:
        cursor = connection.execute(
            """
            DELETE FROM url_feedback
            WHERE id = ?
            """,
            (feedback_id,),
        )

        connection.commit()

    return cursor.rowcount > 0
