from __future__ import annotations


def classification_metrics(
    *,
    true_positive: int,
    true_negative: int,
    false_positive: int,
    false_negative: int,
) -> dict:
    total = (
        true_positive
        + true_negative
        + false_positive
        + false_negative
    )

    accuracy = (
        (
            true_positive
            + true_negative
        )
        / total
        if total
        else 0.0
    )

    precision_denominator = (
        true_positive
        + false_positive
    )

    precision = (
        true_positive
        / precision_denominator
        if precision_denominator
        else 0.0
    )

    recall_denominator = (
        true_positive
        + false_negative
    )

    recall = (
        true_positive
        / recall_denominator
        if recall_denominator
        else 0.0
    )

    specificity_denominator = (
        true_negative
        + false_positive
    )

    specificity = (
        true_negative
        / specificity_denominator
        if specificity_denominator
        else 0.0
    )

    f1 = (
        2
        * precision
        * recall
        / (
            precision
            + recall
        )
        if (
            precision
            + recall
        )
        else 0.0
    )

    false_positive_rate = (
        false_positive
        / specificity_denominator
        if specificity_denominator
        else 0.0
    )

    false_negative_rate = (
        false_negative
        / recall_denominator
        if recall_denominator
        else 0.0
    )

    balanced_accuracy = (
        (
            recall
            + specificity
        )
        / 2
    )

    return {
        "accuracy": round(
            accuracy,
            4,
        ),
        "precision": round(
            precision,
            4,
        ),
        "recall": round(
            recall,
            4,
        ),
        "specificity": round(
            specificity,
            4,
        ),
        "f1": round(
            f1,
            4,
        ),
        "balanced_accuracy": round(
            balanced_accuracy,
            4,
        ),
        "false_positive_rate": round(
            false_positive_rate,
            4,
        ),
        "false_negative_rate": round(
            false_negative_rate,
            4,
        ),
        "confusion_matrix": {
            "true_positive": (
                true_positive
            ),
            "true_negative": (
                true_negative
            ),
            "false_positive": (
                false_positive
            ),
            "false_negative": (
                false_negative
            ),
        },
    }
