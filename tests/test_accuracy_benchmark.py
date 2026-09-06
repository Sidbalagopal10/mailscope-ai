from __future__ import annotations

import json

from app.evaluation import (
    benchmark_runner,
)


def test_dataset_loads():
    dataset = (
        benchmark_runner.load_dataset()
    )

    assert dataset[
        "version"
    ] == "1.0.0"

    assert len(
        dataset[
            "cases"
        ]
    ) >= 20


def test_metrics_perfect_predictions():
    results = [
        {
            "true_label": 0,
            "score": 10,
        },
        {
            "true_label": 0,
            "score": 20,
        },
        {
            "true_label": 1,
            "score": 80,
        },
        {
            "true_label": 1,
            "score": 90,
        },
    ]

    metrics = (
        benchmark_runner
        .metrics_for_threshold(
            results,
            60,
        )
    )

    assert metrics[
        "accuracy"
    ] == 1.0

    assert metrics[
        "false_positive_rate"
    ] == 0.0

    assert metrics[
        "false_negative_rate"
    ] == 0.0


def test_threshold_selection_respects_fpr():
    metrics = [
        {
            "threshold": 40,
            "balanced_accuracy": 0.95,
            "f1": 0.94,
            "recall": 1.0,
            "false_positive_rate": 0.30,
        },
        {
            "threshold": 60,
            "balanced_accuracy": 0.90,
            "f1": 0.90,
            "recall": 0.90,
            "false_positive_rate": 0.05,
        },
    ]

    selected = (
        benchmark_runner.choose_threshold(
            metrics,
            maximum_false_positive_rate=0.10,
        )
    )

    assert selected[
        "threshold"
    ] == 60


def test_benchmark_does_not_change_threshold(
    tmp_path,
    monkeypatch,
):
    report_path = (
        tmp_path
        / "report.json"
    )

    monkeypatch.setattr(
        benchmark_runner,
        "DEFAULT_REPORT_PATH",
        report_path,
    )

    report = (
        benchmark_runner.run_benchmark()
    )

    assert report[
        "automatic_threshold_change"
    ] is False

    assert report[
        "manual_review_required"
    ] is True

    assert report[
        "real_world_accuracy_claim"
    ] is False

    assert report_path.exists()


def test_legitimate_assignment_is_not_phishing():
    dataset = (
        benchmark_runner.load_dataset()
    )

    case = next(
        item
        for item in dataset[
            "cases"
        ]
        if item[
            "id"
        ]
        == "legit-university-assignment"
    )

    result = (
        benchmark_runner.run_case(
            case
        )
    )

    assert result[
        "true_label"
    ] == 0

    assert result[
        "score"
    ] < 60


def test_gift_card_bec_is_detected():
    dataset = (
        benchmark_runner.load_dataset()
    )

    case = next(
        item
        for item in dataset[
            "cases"
        ]
        if item[
            "id"
        ]
        == "phish-gift-card-bec"
    )

    result = (
        benchmark_runner.run_case(
            case
        )
    )

    assert result[
        "true_label"
    ] == 1

    assert result[
        "score"
    ] >= 60


def test_report_serializable():
    report = (
        benchmark_runner.run_benchmark()
    )

    json.dumps(
        report
    )
