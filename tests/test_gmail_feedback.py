from __future__ import annotations

from app.gmail_feedback import (
    review_store,
)


def test_review_labels():
    assert (
        review_store.reviewer_label_for_verdict(
            "correct_phishing"
        )
        == 1
    )

    assert (
        review_store.reviewer_label_for_verdict(
            "false_negative"
        )
        == 1
    )

    assert (
        review_store.reviewer_label_for_verdict(
            "false_positive"
        )
        == 0
    )

    assert (
        review_store.reviewer_label_for_verdict(
            "correct_legitimate"
        )
        == 0
    )

    assert (
        review_store.reviewer_label_for_verdict(
            "unsure"
        )
        is None
    )


def test_unsure_is_not_training_eligible():
    assert not review_store.training_eligible(
        "unsure"
    )


def test_decided_review_is_training_eligible():
    assert review_store.training_eligible(
        "correct_phishing"
    )


def test_save_review(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        review_store,
        "DATABASE_PATH",
        tmp_path / "reviews.db",
    )

    monkeypatch.setattr(
        review_store,
        "EXPORT_PATH",
        tmp_path / "training.jsonl",
    )

    saved = review_store.save_review(
        message_id="message-1",
        thread_id="thread-1",
        subject="Urgent password verification",
        sender_address="sender@example.com",
        predicted_score=90,
        predicted_risk_level="critical",
        predicted_classification=(
            "likely_phishing"
        ),
        proposed_labels=[
            "PHISHING_HIGH",
            "PROCESSED",
        ],
        review_verdict=(
            "correct_phishing"
        ),
        reviewer_notes=(
            "Credential-harvesting link."
        ),
    )

    assert saved[
        "reviewer_label"
    ] == 1

    assert saved[
        "include_in_training"
    ]

    assert (
        tmp_path / "training.jsonl"
    ).exists()


def test_false_positive_exports_benign_label(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        review_store,
        "DATABASE_PATH",
        tmp_path / "reviews.db",
    )

    monkeypatch.setattr(
        review_store,
        "EXPORT_PATH",
        tmp_path / "training.jsonl",
    )

    saved = review_store.save_review(
        message_id="message-2",
        thread_id="thread-2",
        subject="Assignment due tonight",
        sender_address="professor@example.edu",
        predicted_score=70,
        predicted_risk_level="high",
        predicted_classification=(
            "high_risk"
        ),
        proposed_labels=[
            "PHISHING_HIGH"
        ],
        review_verdict=(
            "false_positive"
        ),
    )

    assert saved[
        "reviewer_label"
    ] == 0

    assert saved[
        "include_in_training"
    ]


def test_review_summary(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        review_store,
        "DATABASE_PATH",
        tmp_path / "reviews.db",
    )

    monkeypatch.setattr(
        review_store,
        "EXPORT_PATH",
        tmp_path / "training.jsonl",
    )

    for index, verdict in enumerate(
        [
            "correct_phishing",
            "correct_legitimate",
            "false_positive",
            "unsure",
        ],
        start=1,
    ):
        review_store.save_review(
            message_id=f"message-{index}",
            thread_id=None,
            subject="Test",
            sender_address="sender@example.com",
            predicted_score=50,
            predicted_risk_level="moderate",
            predicted_classification=(
                "needs_review"
            ),
            proposed_labels=[
                "PHISHING_MODERATE"
            ],
            review_verdict=verdict,
        )

    summary = review_store.get_summary()

    assert summary[
        "total_reviews"
    ] == 4

    assert summary[
        "training_eligible"
    ] == 3

    assert summary[
        "reviewed_accuracy_percentage"
    ] == 66.67
