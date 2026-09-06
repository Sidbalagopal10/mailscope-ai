from pathlib import Path

import pytest

import app.feedback.service as service


@pytest.fixture()
def temporary_feedback_database(
    tmp_path: Path,
    monkeypatch,
):
    database_path = (
        tmp_path / "feedback_test.db"
    )

    monkeypatch.setattr(
        service,
        "DATABASE_PATH",
        database_path,
    )

    service.initialize_feedback_database()

    return database_path


def test_save_correct_prediction(
    temporary_feedback_database,
):
    record = service.save_feedback(
        url="https://example.com/",
        predicted_label=0,
        predicted_probability=0.08,
        final_score=12.0,
        risk_level="low",
        is_prediction_correct=True,
        confirmed_label=0,
        model_version="test-model",
        model_type="test-classifier",
    )

    assert record["id"] > 0
    assert record["predicted_label"] == 0
    assert record["confirmed_label"] == 0
    assert (
        record["is_prediction_correct"]
        is True
    )


def test_save_incorrect_prediction(
    temporary_feedback_database,
):
    record = service.save_feedback(
        url="http://example.test/login",
        predicted_label=0,
        predicted_probability=0.35,
        final_score=44.0,
        risk_level="medium",
        is_prediction_correct=False,
        confirmed_label=1,
    )

    assert record["predicted_label"] == 0
    assert record["confirmed_label"] == 1
    assert (
        record["is_prediction_correct"]
        is False
    )


def test_reject_inconsistent_feedback(
    temporary_feedback_database,
):
    with pytest.raises(
        service.FeedbackError
    ):
        service.save_feedback(
            url="https://example.com/",
            predicted_label=0,
            is_prediction_correct=False,
            confirmed_label=0,
        )


def test_feedback_summary(
    temporary_feedback_database,
):
    service.save_feedback(
        url="https://safe.example/",
        predicted_label=0,
        is_prediction_correct=True,
        confirmed_label=0,
    )

    service.save_feedback(
        url="http://phish.example/login",
        predicted_label=0,
        is_prediction_correct=False,
        confirmed_label=1,
    )

    summary = (
        service.get_feedback_summary()
    )

    assert summary[
        "total_feedback"
    ] == 2

    assert summary[
        "correct_predictions"
    ] == 1

    assert summary[
        "incorrect_predictions"
    ] == 1

    assert summary[
        "confirmed_phishing"
    ] == 1

    assert summary[
        "confirmed_benign"
    ] == 1

    assert summary[
        "confusion_matrix"
    ]["false_negatives"] == 1


def test_list_feedback(
    temporary_feedback_database,
):
    service.save_feedback(
        url="https://first.example/",
        predicted_label=0,
        is_prediction_correct=True,
        confirmed_label=0,
    )

    service.save_feedback(
        url="http://second.example/login",
        predicted_label=1,
        is_prediction_correct=True,
        confirmed_label=1,
    )

    records = service.list_feedback()

    assert len(records) == 2
    assert records[0]["id"] > records[1]["id"]
