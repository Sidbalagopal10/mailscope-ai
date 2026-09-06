from __future__ import annotations

import json

import numpy as np
import pytest

from app.model_governance import (
    review_calibration as calibration,
)


def create_examples(
    phishing: int,
    legitimate: int,
):
    examples = []

    for index in range(
        legitimate
    ):
        examples.append(
            {
                "message_id": (
                    f"legitimate-{index}"
                ),
                "predicted_score": (
                    10
                    + index % 25
                ),
                "predicted_risk_level": (
                    "low"
                    if index % 2 == 0
                    else "moderate"
                ),
                "predicted_classification": (
                    "likely_legitimate"
                ),
                "reviewer_label": 0,
            }
        )

    for index in range(
        phishing
    ):
        examples.append(
            {
                "message_id": (
                    f"phishing-{index}"
                ),
                "predicted_score": (
                    65
                    + index % 30
                ),
                "predicted_risk_level": (
                    "high"
                    if index % 2 == 0
                    else "critical"
                ),
                "predicted_classification": (
                    "likely_phishing"
                ),
                "reviewer_label": 1,
            }
        )

    return examples


def write_examples(
    path,
    examples,
):
    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        for example in examples:
            file.write(
                json.dumps(
                    example
                )
                + "\n"
            )


def test_training_gate_closed_for_small_dataset():
    summary = calibration.dataset_summary(
        create_examples(
            phishing=5,
            legitimate=5,
        )
    )

    assert not summary[
        "training_gate_open"
    ]


def test_training_gate_requires_both_classes():
    summary = calibration.dataset_summary(
        create_examples(
            phishing=40,
            legitimate=0,
        )
    )

    assert not summary[
        "training_gate_open"
    ]


def test_training_gate_opens_for_balanced_dataset():
    summary = calibration.dataset_summary(
        create_examples(
            phishing=20,
            legitimate=20,
        )
    )

    assert summary[
        "training_gate_open"
    ]


def test_feature_vector_shape():
    features = calibration.example_to_features(
        {
            "predicted_score": 80,
            "predicted_risk_level": "high",
            "predicted_classification": (
                "likely_phishing"
            ),
        }
    )

    assert len(
        features
    ) == len(
        calibration.feature_names()
    )

    assert features[0] == 80


def test_metrics_include_false_positive_rate():
    metrics = calibration.classification_metrics(
        np.asarray(
            [
                0,
                0,
                1,
                1,
            ]
        ),
        np.asarray(
            [
                0,
                1,
                1,
                1,
            ]
        ),
        np.asarray(
            [
                0.1,
                0.8,
                0.7,
                0.9,
            ]
        ),
    )

    assert metrics[
        "false_positive_rate"
    ] == 0.5

    assert metrics[
        "true_positive"
    ] == 2


def test_candidate_is_staged_not_promoted(
    tmp_path,
    monkeypatch,
):
    review_path = (
        tmp_path
        / "reviews.jsonl"
    )

    write_examples(
        review_path,
        create_examples(
            phishing=25,
            legitimate=25,
        ),
    )

    candidate_path = (
        tmp_path
        / "candidate.joblib"
    )

    report_path = (
        tmp_path
        / "report.json"
    )

    monkeypatch.setattr(
        calibration,
        "LATEST_CANDIDATE_PATH",
        candidate_path,
    )

    monkeypatch.setattr(
        calibration,
        "LATEST_REPORT_PATH",
        report_path,
    )

    monkeypatch.setattr(
        calibration,
        "CANDIDATE_DIRECTORY",
        tmp_path,
    )

    report = (
        calibration.train_and_evaluate_candidate(
            review_path=review_path
        )
    )

    assert candidate_path.exists()
    assert report[
        "candidate_saved"
    ]

    assert not report[
        "candidate_promoted"
    ]

    assert not report[
        "active_model_changed"
    ]

    assert not report[
        "safety_controls"
    ][
        "automatic_model_replacement"
    ]


def test_closed_gate_refuses_training(
    tmp_path,
):
    review_path = (
        tmp_path
        / "reviews.jsonl"
    )

    write_examples(
        review_path,
        create_examples(
            phishing=3,
            legitimate=3,
        ),
    )

    with pytest.raises(
        calibration.CalibrationGateError
    ):
        calibration.train_and_evaluate_candidate(
            review_path=review_path
        )


def test_promotion_gate_rejects_high_false_positive_rate():
    result = calibration.evaluate_promotion_gate(
        baseline_metrics={
            "balanced_accuracy": 0.70,
            "f1": 0.70,
            "false_positive_rate": 0.05,
        },
        candidate_metrics={
            "balanced_accuracy": 0.80,
            "f1": 0.80,
            "false_positive_rate": 0.30,
        },
    )

    assert not result[
        "eligible_for_manual_promotion"
    ]

    assert not result[
        "false_positive_rate_acceptable"
    ]

    assert not result[
        "automatic_promotion_permitted"
    ]
