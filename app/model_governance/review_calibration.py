from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


REVIEW_DATA_PATH = Path(
    "data/gmail_feedback/reviewed_training_examples.jsonl"
)

CANDIDATE_DIRECTORY = Path(
    "data/model_governance/candidates"
)

LATEST_REPORT_PATH = Path(
    "data/model_governance/latest_calibration_report.json"
)

LATEST_CANDIDATE_PATH = (
    CANDIDATE_DIRECTORY
    / "latest_review_calibrator.joblib"
)

MINIMUM_TOTAL_EXAMPLES = 40
MINIMUM_EXAMPLES_PER_CLASS = 15
TEST_SIZE = 0.30
RANDOM_STATE = 42

BASELINE_THRESHOLD = 60.0
CANDIDATE_THRESHOLD = 0.50


class CalibrationGateError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def normalize_risk_level(
    value: str | None,
) -> str:
    normalized = str(
        value or ""
    ).strip().lower()

    if normalized not in {
        "low",
        "moderate",
        "high",
        "critical",
    }:
        return "unknown"

    return normalized


def normalize_classification(
    value: str | None,
) -> str:
    return str(
        value or ""
    ).strip().lower()


def load_reviewed_examples(
    path: Path = REVIEW_DATA_PATH,
) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    examples: list[
        dict[str, Any]
    ] = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line_number, line in enumerate(
            file,
            start=1,
        ):
            stripped = line.strip()

            if not stripped:
                continue

            try:
                item = json.loads(
                    stripped
                )

            except json.JSONDecodeError:
                continue

            label = item.get(
                "reviewer_label"
            )

            if label not in {
                0,
                1,
            }:
                continue

            try:
                predicted_score = float(
                    item.get(
                        "predicted_score",
                        0,
                    )
                )

            except (
                TypeError,
                ValueError,
            ):
                continue

            examples.append(
                {
                    **item,
                    "predicted_score": max(
                        0.0,
                        min(
                            predicted_score,
                            100.0,
                        ),
                    ),
                    "reviewer_label": int(
                        label
                    ),
                    "source_line": line_number,
                }
            )

    return examples


def feature_names() -> list[str]:
    return [
        "predicted_score",
        "risk_low",
        "risk_moderate",
        "risk_high",
        "risk_critical",
        "classification_likely_legitimate",
        "classification_needs_review",
        "classification_high_risk",
        "classification_likely_phishing",
    ]


def example_to_features(
    example: dict[str, Any],
) -> list[float]:
    score = float(
        example.get(
            "predicted_score",
            0,
        )
        or 0
    )

    risk_level = normalize_risk_level(
        example.get(
            "predicted_risk_level"
        )
    )

    classification = normalize_classification(
        example.get(
            "predicted_classification"
        )
    )

    return [
        score,
        float(
            risk_level == "low"
        ),
        float(
            risk_level == "moderate"
        ),
        float(
            risk_level == "high"
        ),
        float(
            risk_level == "critical"
        ),
        float(
            classification
            == "likely_legitimate"
        ),
        float(
            classification
            == "needs_review"
        ),
        float(
            classification
            == "high_risk"
        ),
        float(
            classification
            == "likely_phishing"
        ),
    ]


def build_dataset(
    examples: list[
        dict[str, Any]
    ],
) -> tuple[
    np.ndarray,
    np.ndarray,
]:
    features = np.asarray(
        [
            example_to_features(
                example
            )
            for example in examples
        ],
        dtype=float,
    )

    labels = np.asarray(
        [
            int(
                example[
                    "reviewer_label"
                ]
            )
            for example in examples
        ],
        dtype=int,
    )

    return features, labels


def dataset_summary(
    examples: list[
        dict[str, Any]
    ],
) -> dict[str, Any]:
    phishing_count = sum(
        1
        for example in examples
        if example[
            "reviewer_label"
        ]
        == 1
    )

    legitimate_count = sum(
        1
        for example in examples
        if example[
            "reviewer_label"
        ]
        == 0
    )

    total = len(
        examples
    )

    return {
        "total_examples": total,
        "phishing_examples": phishing_count,
        "legitimate_examples": legitimate_count,
        "minimum_total_required": (
            MINIMUM_TOTAL_EXAMPLES
        ),
        "minimum_per_class_required": (
            MINIMUM_EXAMPLES_PER_CLASS
        ),
        "total_requirement_met": bool(
            total
            >= MINIMUM_TOTAL_EXAMPLES
        ),
        "phishing_requirement_met": bool(
            phishing_count
            >= MINIMUM_EXAMPLES_PER_CLASS
        ),
        "legitimate_requirement_met": bool(
            legitimate_count
            >= MINIMUM_EXAMPLES_PER_CLASS
        ),
        "training_gate_open": bool(
            total
            >= MINIMUM_TOTAL_EXAMPLES
            and phishing_count
            >= MINIMUM_EXAMPLES_PER_CLASS
            and legitimate_count
            >= MINIMUM_EXAMPLES_PER_CLASS
        ),
    }


def validate_training_gate(
    examples: list[
        dict[str, Any]
    ],
) -> dict[str, Any]:
    summary = dataset_summary(
        examples
    )

    if not summary[
        "training_gate_open"
    ]:
        raise CalibrationGateError(
            "Training gate is closed. Required: "
            f"{MINIMUM_TOTAL_EXAMPLES} total reviewed examples, "
            f"including at least {MINIMUM_EXAMPLES_PER_CLASS} "
            "phishing and "
            f"{MINIMUM_EXAMPLES_PER_CLASS} legitimate examples. "
            f"Current: {summary['total_examples']} total, "
            f"{summary['phishing_examples']} phishing, "
            f"{summary['legitimate_examples']} legitimate."
        )

    return summary


def classification_metrics(
    true_labels: np.ndarray,
    predicted_labels: np.ndarray,
    probabilities: np.ndarray | None = None,
) -> dict[str, Any]:
    matrix = confusion_matrix(
        true_labels,
        predicted_labels,
        labels=[
            0,
            1,
        ],
    )

    true_negative = int(
        matrix[0, 0]
    )

    false_positive = int(
        matrix[0, 1]
    )

    false_negative = int(
        matrix[1, 0]
    )

    true_positive = int(
        matrix[1, 1]
    )

    negative_total = (
        true_negative
        + false_positive
    )

    positive_total = (
        true_positive
        + false_negative
    )

    false_positive_rate = (
        false_positive
        / negative_total
        if negative_total
        else 0.0
    )

    false_negative_rate = (
        false_negative
        / positive_total
        if positive_total
        else 0.0
    )

    auc = None

    if (
        probabilities is not None
        and len(
            np.unique(
                true_labels
            )
        )
        == 2
    ):
        auc = float(
            roc_auc_score(
                true_labels,
                probabilities,
            )
        )

    return {
        "accuracy": round(
            float(
                accuracy_score(
                    true_labels,
                    predicted_labels,
                )
            ),
            4,
        ),
        "balanced_accuracy": round(
            float(
                balanced_accuracy_score(
                    true_labels,
                    predicted_labels,
                )
            ),
            4,
        ),
        "precision": round(
            float(
                precision_score(
                    true_labels,
                    predicted_labels,
                    zero_division=0,
                )
            ),
            4,
        ),
        "recall": round(
            float(
                recall_score(
                    true_labels,
                    predicted_labels,
                    zero_division=0,
                )
            ),
            4,
        ),
        "f1": round(
            float(
                f1_score(
                    true_labels,
                    predicted_labels,
                    zero_division=0,
                )
            ),
            4,
        ),
        "roc_auc": (
            round(
                auc,
                4,
            )
            if auc is not None
            else None
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
        "true_positive": (
            true_positive
        ),
        "false_positive_rate": round(
            float(
                false_positive_rate
            ),
            4,
        ),
        "false_negative_rate": round(
            float(
                false_negative_rate
            ),
            4,
        ),
    }


def evaluate_promotion_gate(
    *,
    baseline_metrics: dict[
        str,
        Any,
    ],
    candidate_metrics: dict[
        str,
        Any,
    ],
) -> dict[str, Any]:
    baseline_balanced_accuracy = float(
        baseline_metrics.get(
            "balanced_accuracy",
            0,
        )
        or 0
    )

    candidate_balanced_accuracy = float(
        candidate_metrics.get(
            "balanced_accuracy",
            0,
        )
        or 0
    )

    baseline_f1 = float(
        baseline_metrics.get(
            "f1",
            0,
        )
        or 0
    )

    candidate_f1 = float(
        candidate_metrics.get(
            "f1",
            0,
        )
        or 0
    )

    baseline_false_positive_rate = float(
        baseline_metrics.get(
            "false_positive_rate",
            0,
        )
        or 0
    )

    candidate_false_positive_rate = float(
        candidate_metrics.get(
            "false_positive_rate",
            0,
        )
        or 0
    )

    balanced_accuracy_improved = bool(
        candidate_balanced_accuracy
        >= baseline_balanced_accuracy
        + 0.01
    )

    f1_not_materially_worse = bool(
        candidate_f1
        >= baseline_f1
        - 0.02
    )

    false_positive_rate_acceptable = bool(
        candidate_false_positive_rate
        <= baseline_false_positive_rate
        + 0.05
    )

    candidate_minimum_quality = bool(
        candidate_balanced_accuracy
        >= 0.65
    )

    eligible_for_manual_promotion = all(
        [
            balanced_accuracy_improved,
            f1_not_materially_worse,
            false_positive_rate_acceptable,
            candidate_minimum_quality,
        ]
    )

    return {
        "eligible_for_manual_promotion": (
            eligible_for_manual_promotion
        ),
        "balanced_accuracy_improved": (
            balanced_accuracy_improved
        ),
        "f1_not_materially_worse": (
            f1_not_materially_worse
        ),
        "false_positive_rate_acceptable": (
            false_positive_rate_acceptable
        ),
        "candidate_minimum_quality": (
            candidate_minimum_quality
        ),
        "balanced_accuracy_change": round(
            candidate_balanced_accuracy
            - baseline_balanced_accuracy,
            4,
        ),
        "f1_change": round(
            candidate_f1
            - baseline_f1,
            4,
        ),
        "false_positive_rate_change": round(
            candidate_false_positive_rate
            - baseline_false_positive_rate,
            4,
        ),
        "automatic_promotion_permitted": False,
        "manual_review_required": True,
    }


def build_candidate_pipeline() -> Pipeline:
    return Pipeline(
        [
            (
                "scaler",
                StandardScaler(),
            ),
            (
                "classifier",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=2000,
                    random_state=(
                        RANDOM_STATE
                    ),
                ),
            ),
        ]
    )


def train_and_evaluate_candidate(
    *,
    review_path: Path = REVIEW_DATA_PATH,
) -> dict[str, Any]:
    examples = load_reviewed_examples(
        review_path
    )

    summary = validate_training_gate(
        examples
    )

    features, labels = build_dataset(
        examples
    )

    (
        train_features,
        test_features,
        train_labels,
        test_labels,
    ) = train_test_split(
        features,
        labels,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=labels,
    )

    pipeline = build_candidate_pipeline()

    pipeline.fit(
        train_features,
        train_labels,
    )

    candidate_probabilities = (
        pipeline.predict_proba(
            test_features
        )[:, 1]
    )

    candidate_predictions = (
        candidate_probabilities
        >= CANDIDATE_THRESHOLD
    ).astype(
        int
    )

    baseline_scores = (
        test_features[:, 0]
    )

    baseline_probabilities = np.clip(
        baseline_scores
        / 100.0,
        0.0,
        1.0,
    )

    baseline_predictions = (
        baseline_scores
        >= BASELINE_THRESHOLD
    ).astype(
        int
    )

    baseline_metrics = classification_metrics(
        test_labels,
        baseline_predictions,
        baseline_probabilities,
    )

    candidate_metrics = classification_metrics(
        test_labels,
        candidate_predictions,
        candidate_probabilities,
    )

    promotion_gate = evaluate_promotion_gate(
        baseline_metrics=(
            baseline_metrics
        ),
        candidate_metrics=(
            candidate_metrics
        ),
    )

    CANDIDATE_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    candidate_payload = {
        "pipeline": pipeline,
        "feature_names": (
            feature_names()
        ),
        "candidate_threshold": (
            CANDIDATE_THRESHOLD
        ),
        "trained_at": utc_now(),
        "training_examples": int(
            len(
                train_labels
            )
        ),
        "holdout_examples": int(
            len(
                test_labels
            )
        ),
        "review_data_path": str(
            review_path
        ),
        "status": "staged_candidate",
        "promoted": False,
    }

    joblib.dump(
        candidate_payload,
        LATEST_CANDIDATE_PATH,
    )

    report = {
        "created_at": utc_now(),
        "status": "evaluation_complete",
        "candidate_model_path": str(
            LATEST_CANDIDATE_PATH
        ),
        "candidate_saved": True,
        "candidate_promoted": False,
        "active_model_changed": False,
        "dataset": summary,
        "split": {
            "training_examples": int(
                len(
                    train_labels
                )
            ),
            "holdout_examples": int(
                len(
                    test_labels
                )
            ),
            "test_fraction": (
                TEST_SIZE
            ),
            "random_state": (
                RANDOM_STATE
            ),
            "stratified": True,
        },
        "baseline": {
            "description": (
                "Current raw score threshold"
            ),
            "threshold": (
                BASELINE_THRESHOLD
            ),
            "metrics": baseline_metrics,
        },
        "candidate": {
            "description": (
                "Human-review score calibrator"
            ),
            "threshold": (
                CANDIDATE_THRESHOLD
            ),
            "metrics": candidate_metrics,
            "features": feature_names(),
        },
        "promotion_gate": (
            promotion_gate
        ),
        "safety_controls": {
            "automatic_training_from_unreviewed_mail": False,
            "automatic_model_replacement": False,
            "candidate_staging_only": True,
            "holdout_evaluation_required": True,
            "balanced_class_minimum_required": True,
            "manual_promotion_required": True,
        },
    }

    LATEST_REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    LATEST_REPORT_PATH.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    return report


def get_gate_status(
    *,
    review_path: Path = REVIEW_DATA_PATH,
) -> dict[str, Any]:
    examples = load_reviewed_examples(
        review_path
    )

    summary = dataset_summary(
        examples
    )

    latest_report = None

    if LATEST_REPORT_PATH.exists():
        try:
            latest_report = json.loads(
                LATEST_REPORT_PATH.read_text(
                    encoding="utf-8"
                )
            )

        except json.JSONDecodeError:
            latest_report = None

    return {
        "dataset": summary,
        "latest_report_available": bool(
            latest_report
        ),
        "latest_report": latest_report,
        "review_data_path": str(
            review_path
        ),
        "candidate_path": str(
            LATEST_CANDIDATE_PATH
        ),
        "candidate_exists": (
            LATEST_CANDIDATE_PATH.exists()
        ),
        "active_model_changed": False,
    }


def predict_with_candidate(
    example: dict[str, Any],
) -> dict[str, Any]:
    if not LATEST_CANDIDATE_PATH.exists():
        raise CalibrationGateError(
            "No staged calibration candidate exists."
        )

    payload = joblib.load(
        LATEST_CANDIDATE_PATH
    )

    pipeline = payload.get(
        "pipeline"
    )

    if pipeline is None:
        raise CalibrationGateError(
            "The candidate file does not contain a pipeline."
        )

    features = np.asarray(
        [
            example_to_features(
                example
            )
        ],
        dtype=float,
    )

    probability = float(
        pipeline.predict_proba(
            features
        )[0, 1]
    )

    threshold = float(
        payload.get(
            "candidate_threshold",
            CANDIDATE_THRESHOLD,
        )
    )

    return {
        "phishing_probability": round(
            probability,
            6,
        ),
        "candidate_prediction": int(
            probability
            >= threshold
        ),
        "threshold": threshold,
        "candidate_status": (
            payload.get(
                "status"
            )
        ),
        "candidate_promoted": bool(
            payload.get(
                "promoted",
                False,
            )
        ),
        "advisory_only": True,
    }
