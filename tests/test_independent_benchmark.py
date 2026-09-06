from __future__ import annotations

from app.benchmarking.metrics import (
    classification_metrics,
)


def test_metrics_perfect():
    metrics = classification_metrics(
        true_positive=50,
        true_negative=50,
        false_positive=0,
        false_negative=0,
    )

    assert (
        metrics[
            "accuracy"
        ]
        == 1.0
    )

    assert (
        metrics[
            "f1"
        ]
        == 1.0
    )


def test_false_positive_rate():
    metrics = classification_metrics(
        true_positive=50,
        true_negative=90,
        false_positive=10,
        false_negative=0,
    )

    assert (
        metrics[
            "false_positive_rate"
        ]
        == 0.10
    )
