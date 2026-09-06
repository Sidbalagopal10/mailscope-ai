from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DATABASE_PATH = Path(
    "data/gmail_feedback/reviews.db"
)

EXPORT_PATH = Path(
    "data/gmail_feedback/reviewed_training_examples.jsonl"
)

ALLOWED_REVIEW_VERDICTS = {
    "correct_phishing",
    "false_positive",
    "false_negative",
    "correct_legitimate",
    "unsure",
}


class GmailFeedbackError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


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
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS gmail_message_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL UNIQUE,
                thread_id TEXT,
                subject TEXT,
                sender_address TEXT,
                predicted_score REAL NOT NULL,
                predicted_risk_level TEXT NOT NULL,
                predicted_classification TEXT,
                proposed_labels_json TEXT NOT NULL,
                review_verdict TEXT NOT NULL,
                reviewer_label INTEGER,
                reviewer_notes TEXT,
                include_in_training INTEGER NOT NULL DEFAULT 0,
                reviewed_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS
            idx_gmail_review_verdict
            ON gmail_message_reviews(review_verdict);

            CREATE INDEX IF NOT EXISTS
            idx_gmail_training_eligible
            ON gmail_message_reviews(include_in_training);
            """
        )

        connection.commit()


def normalize_verdict(
    value: str,
) -> str:
    normalized = str(
        value or ""
    ).strip().lower()

    if normalized not in ALLOWED_REVIEW_VERDICTS:
        raise GmailFeedbackError(
            "Unsupported review verdict."
        )

    return normalized


def reviewer_label_for_verdict(
    verdict: str,
) -> int | None:
    normalized = normalize_verdict(
        verdict
    )

    if normalized in {
        "correct_phishing",
        "false_negative",
    }:
        return 1

    if normalized in {
        "false_positive",
        "correct_legitimate",
    }:
        return 0

    return None


def training_eligible(
    verdict: str,
) -> bool:
    return normalize_verdict(
        verdict
    ) != "unsure"


def save_review(
    *,
    message_id: str,
    thread_id: str | None,
    subject: str | None,
    sender_address: str | None,
    predicted_score: float,
    predicted_risk_level: str,
    predicted_classification: str | None,
    proposed_labels: list[str],
    review_verdict: str,
    reviewer_notes: str | None = None,
) -> dict[str, Any]:
    initialize_database()

    normalized_message_id = str(
        message_id or ""
    ).strip()

    if not normalized_message_id:
        raise GmailFeedbackError(
            "A Gmail message ID is required."
        )

    verdict = normalize_verdict(
        review_verdict
    )

    reviewer_label = reviewer_label_for_verdict(
        verdict
    )

    include_in_training = training_eligible(
        verdict
    )

    timestamp = utc_now()

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO gmail_message_reviews (
                message_id,
                thread_id,
                subject,
                sender_address,
                predicted_score,
                predicted_risk_level,
                predicted_classification,
                proposed_labels_json,
                review_verdict,
                reviewer_label,
                reviewer_notes,
                include_in_training,
                reviewed_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(message_id)
            DO UPDATE SET
                thread_id = excluded.thread_id,
                subject = excluded.subject,
                sender_address = excluded.sender_address,
                predicted_score = excluded.predicted_score,
                predicted_risk_level = excluded.predicted_risk_level,
                predicted_classification =
                    excluded.predicted_classification,
                proposed_labels_json =
                    excluded.proposed_labels_json,
                review_verdict = excluded.review_verdict,
                reviewer_label = excluded.reviewer_label,
                reviewer_notes = excluded.reviewer_notes,
                include_in_training =
                    excluded.include_in_training,
                reviewed_at = excluded.reviewed_at,
                updated_at = excluded.updated_at
            """,
            (
                normalized_message_id,
                thread_id,
                subject,
                sender_address,
                float(
                    predicted_score
                ),
                str(
                    predicted_risk_level
                ),
                predicted_classification,
                json.dumps(
                    proposed_labels,
                    sort_keys=True,
                ),
                verdict,
                reviewer_label,
                reviewer_notes,
                int(
                    include_in_training
                ),
                timestamp,
                timestamp,
            ),
        )

        connection.commit()

    result = get_review(
        normalized_message_id
    )

    if result is None:
        raise GmailFeedbackError(
            "The review could not be saved."
        )

    export_training_examples()

    return result


def deserialize_row(
    row: sqlite3.Row,
) -> dict[str, Any]:
    result = dict(
        row
    )

    try:
        result["proposed_labels"] = json.loads(
            result.pop(
                "proposed_labels_json",
                "[]",
            )
        )

    except json.JSONDecodeError:
        result["proposed_labels"] = []

    reviewer_label = result.get(
        "reviewer_label"
    )

    result["reviewer_label"] = (
        int(
            reviewer_label
        )
        if reviewer_label is not None
        else None
    )

    result["include_in_training"] = bool(
        result.get(
            "include_in_training"
        )
    )

    return result


def get_review(
    message_id: str,
) -> dict[str, Any] | None:
    initialize_database()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM gmail_message_reviews
            WHERE message_id = ?
            """,
            (
                str(
                    message_id
                ).strip(),
            ),
        ).fetchone()

    if row is None:
        return None

    return deserialize_row(
        row
    )


def list_reviews(
    limit: int = 500,
) -> list[dict[str, Any]]:
    initialize_database()

    safe_limit = max(
        1,
        min(
            int(
                limit
            ),
            5000,
        ),
    )

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM gmail_message_reviews
            ORDER BY reviewed_at DESC
            LIMIT ?
            """,
            (
                safe_limit,
            ),
        ).fetchall()

    return [
        deserialize_row(
            row
        )
        for row in rows
    ]


def get_summary() -> dict[str, Any]:
    reviews = list_reviews(
        limit=5000
    )

    counts = {
        verdict: 0
        for verdict in ALLOWED_REVIEW_VERDICTS
    }

    for review in reviews:
        verdict = review.get(
            "review_verdict"
        )

        if verdict in counts:
            counts[
                verdict
            ] += 1

    total_reviewed = len(
        reviews
    )

    correct = (
        counts[
            "correct_phishing"
        ]
        + counts[
            "correct_legitimate"
        ]
    )

    incorrect = (
        counts[
            "false_positive"
        ]
        + counts[
            "false_negative"
        ]
    )

    decided = (
        correct
        + incorrect
    )

    reviewed_accuracy = (
        round(
            correct
            / decided
            * 100,
            2,
        )
        if decided
        else None
    )

    return {
        "total_reviews": total_reviewed,
        "training_eligible": sum(
            1
            for review in reviews
            if review.get(
                "include_in_training"
            )
        ),
        "correct_predictions": correct,
        "incorrect_predictions": incorrect,
        "reviewed_accuracy_percentage": (
            reviewed_accuracy
        ),
        **counts,
    }


def export_training_examples() -> Path:
    reviews = [
        review
        for review in list_reviews(
            limit=5000
        )
        if review.get(
            "include_in_training"
        )
        and review.get(
            "reviewer_label"
        )
        in {
            0,
            1,
        }
    ]

    EXPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with EXPORT_PATH.open(
        "w",
        encoding="utf-8",
    ) as file:
        for review in reviews:
            example = {
                "message_id": review[
                    "message_id"
                ],
                "subject": review.get(
                    "subject"
                ),
                "sender_address": review.get(
                    "sender_address"
                ),
                "predicted_score": review.get(
                    "predicted_score"
                ),
                "predicted_risk_level": review.get(
                    "predicted_risk_level"
                ),
                "predicted_classification": review.get(
                    "predicted_classification"
                ),
                "reviewer_label": review.get(
                    "reviewer_label"
                ),
                "review_verdict": review.get(
                    "review_verdict"
                ),
                "reviewed_at": review.get(
                    "reviewed_at"
                ),
                "source": (
                    "explicit_human_review"
                ),
            }

            file.write(
                json.dumps(
                    example,
                    sort_keys=True,
                )
                + "\n"
            )

    return EXPORT_PATH
