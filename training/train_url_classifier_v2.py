from __future__ import annotations

import json
from datetime import (
    datetime,
    timezone,
)
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import (
    HistGradientBoostingClassifier,
)
from sklearn.isotonic import (
    IsotonicRegression,
)
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import (
    GroupShuffleSplit,
)

from app.detection.brand_intelligence import (
    registered_domain_approximation,
)
from app.ml.url_features import (
    extract_url_features,
)


BASE_DATASET_PATH = Path(
    "training/processed/"
    "phishing_url_dataset.csv"
)

ENRICHMENT_PATH = Path(
    "training/data/"
    "accuracy_v2_examples.csv"
)

MODEL_PATH = Path(
    "models/url_classifier.joblib"
)

METADATA_PATH = Path(
    "models/url_classifier_metadata.json"
)

EVALUATION_PATH = Path(
    "models/url_classifier_evaluation.json"
)

RANDOM_SEED = 42
TARGET_PRECISION = 0.90


def hostname(
    url: str,
) -> str:
    value = str(
        url
    ).strip()

    if "://" not in value:
        value = (
            f"http://{value}"
        )

    parsed = urlparse(
        value
    )

    return (
        registered_domain_approximation(
            parsed.hostname or "unknown"
        )
        or "unknown"
    )


def load_dataset() -> pd.DataFrame:
    if not BASE_DATASET_PATH.exists():
        raise FileNotFoundError(
            "Processed Kaggle dataset not "
            f"found: {BASE_DATASET_PATH}"
        )

    base = pd.read_csv(
        BASE_DATASET_PATH,
        low_memory=False,
    )

    base = base[
        [
            "url",
            "label",
        ]
    ].copy()

    if ENRICHMENT_PATH.exists():
        enrichment = pd.read_csv(
            ENRICHMENT_PATH
        )[
            [
                "url",
                "label",
            ]
        ]

        # Repeat the small curated set enough to
        # influence the boundary without overwhelming
        # the much larger Kaggle dataset.
        enrichment = pd.concat(
            [
                enrichment
                for _ in range(12)
            ],
            ignore_index=True,
        )

        dataset = pd.concat(
            [
                base,
                enrichment,
            ],
            ignore_index=True,
        )
    else:
        dataset = base

    dataset = dataset.dropna(
        subset=[
            "url",
            "label",
        ]
    )

    dataset["url"] = (
        dataset["url"]
        .astype(str)
        .str.strip()
    )

    dataset["label"] = (
        dataset["label"]
        .astype(int)
    )

    dataset = dataset[
        dataset["label"].isin(
            [0, 1]
        )
    ]

    dataset = dataset.drop_duplicates(
        subset=[
            "url",
            "label",
        ],
        keep="last",
    ).reset_index(
        drop=True
    )

    dataset["hostname"] = (
        dataset["url"].map(
            hostname
        )
    )

    return dataset


def build_features(
    dataset: pd.DataFrame,
) -> pd.DataFrame:
    rows = []
    total = len(dataset)

    for index, url in enumerate(
        dataset["url"],
        start=1,
    ):
        rows.append(
            extract_url_features(
                url
            )
        )

        if index % 10000 == 0:
            print(
                "Feature extraction:",
                f"{index:,}/{total:,}",
            )

    return pd.DataFrame(
        rows
    ).fillna(0)


def group_split(
    features: pd.DataFrame,
    dataset: pd.DataFrame,
):
    outer = GroupShuffleSplit(
        n_splits=1,
        test_size=0.18,
        random_state=RANDOM_SEED,
    )

    development_indices, test_indices = next(
        outer.split(
            features,
            dataset["label"],
            groups=dataset[
                "hostname"
            ],
        )
    )

    development_features = (
        features.iloc[
            development_indices
        ].reset_index(
            drop=True
        )
    )

    development_dataset = (
        dataset.iloc[
            development_indices
        ].reset_index(
            drop=True
        )
    )

    inner = GroupShuffleSplit(
        n_splits=1,
        test_size=0.18,
        random_state=(
            RANDOM_SEED + 1
        ),
    )

    train_indices, calibration_indices = next(
        inner.split(
            development_features,
            development_dataset[
                "label"
            ],
            groups=development_dataset[
                "hostname"
            ],
        )
    )

    return {
        "x_train": (
            development_features.iloc[
                train_indices
            ].reset_index(
                drop=True
            )
        ),
        "y_train": (
            development_dataset[
                "label"
            ].iloc[
                train_indices
            ].reset_index(
                drop=True
            )
        ),
        "x_calibration": (
            development_features.iloc[
                calibration_indices
            ].reset_index(
                drop=True
            )
        ),
        "y_calibration": (
            development_dataset[
                "label"
            ].iloc[
                calibration_indices
            ].reset_index(
                drop=True
            )
        ),
        "x_test": (
            features.iloc[
                test_indices
            ].reset_index(
                drop=True
            )
        ),
        "y_test": (
            dataset["label"].iloc[
                test_indices
            ].reset_index(
                drop=True
            )
        ),
        "train_hosts": set(
            development_dataset[
                "hostname"
            ].iloc[
                train_indices
            ]
        ),
        "calibration_hosts": set(
            development_dataset[
                "hostname"
            ].iloc[
                calibration_indices
            ]
        ),
        "test_hosts": set(
            dataset["hostname"].iloc[
                test_indices
            ]
        ),
    }


def sample_weights(
    labels: pd.Series,
) -> np.ndarray:
    counts = (
        labels.value_counts()
    )

    total = len(labels)

    weights = {
        int(label): (
            total
            / (
                len(counts)
                * int(count)
            )
        )
        for label, count in (
            counts.items()
        )
    }

    return labels.map(
        weights
    ).to_numpy()


def choose_threshold(
    labels: pd.Series,
    probabilities: np.ndarray,
) -> float:
    precision, recall, thresholds = (
        precision_recall_curve(
            labels,
            probabilities,
        )
    )

    eligible = []

    for index, threshold in enumerate(
        thresholds
    ):
        current_precision = (
            precision[index]
        )

        current_recall = (
            recall[index]
        )

        if (
            current_precision
            >= TARGET_PRECISION
        ):
            eligible.append(
                (
                    current_recall,
                    current_precision,
                    float(threshold),
                )
            )

    if eligible:
        eligible.sort(
            reverse=True
        )

        return float(
            eligible[0][2]
        )

    f1_values = (
        2
        * precision[:-1]
        * recall[:-1]
        / (
            precision[:-1]
            + recall[:-1]
            + 1e-12
        )
    )

    best_index = int(
        np.argmax(
            f1_values
        )
    )

    return float(
        thresholds[
            best_index
        ]
    )


def metrics(
    labels: pd.Series,
    probabilities: np.ndarray,
    threshold: float,
) -> dict:
    predictions = (
        probabilities
        >= threshold
    ).astype(int)

    matrix = confusion_matrix(
        labels,
        predictions,
        labels=[
            0,
            1,
        ],
    )

    return {
        "accuracy": round(
            float(
                accuracy_score(
                    labels,
                    predictions,
                )
            ),
            6,
        ),
        "precision": round(
            float(
                precision_score(
                    labels,
                    predictions,
                    zero_division=0,
                )
            ),
            6,
        ),
        "recall": round(
            float(
                recall_score(
                    labels,
                    predictions,
                    zero_division=0,
                )
            ),
            6,
        ),
        "f1_score": round(
            float(
                f1_score(
                    labels,
                    predictions,
                    zero_division=0,
                )
            ),
            6,
        ),
        "roc_auc": round(
            float(
                roc_auc_score(
                    labels,
                    probabilities,
                )
            ),
            6,
        ),
        "average_precision": round(
            float(
                average_precision_score(
                    labels,
                    probabilities,
                )
            ),
            6,
        ),
        "true_negatives": int(
            matrix[0][0]
        ),
        "false_positives": int(
            matrix[0][1]
        ),
        "false_negatives": int(
            matrix[1][0]
        ),
        "true_positives": int(
            matrix[1][1]
        ),
        "confusion_matrix": (
            matrix.tolist()
        ),
    }


def main() -> None:
    dataset = load_dataset()

    print(
        "Dataset records:",
        f"{len(dataset):,}",
    )

    print(
        dataset["label"]
        .value_counts()
        .sort_index()
    )

    features = build_features(
        dataset
    )

    split = group_split(
        features,
        dataset,
    )

    overlap = (
        split["train_hosts"]
        & split[
            "calibration_hosts"
        ]
    ) | (
        split["train_hosts"]
        & split["test_hosts"]
    ) | (
        split[
            "calibration_hosts"
        ]
        & split["test_hosts"]
    )

    if overlap:
        raise RuntimeError(
            "Hostname leakage detected."
        )

    classifier = (
        HistGradientBoostingClassifier(
            learning_rate=0.06,
            max_iter=400,
            max_leaf_nodes=31,
            min_samples_leaf=30,
            l2_regularization=1.5,
            early_stopping=True,
            validation_fraction=0.10,
            n_iter_no_change=25,
            random_state=RANDOM_SEED,
        )
    )

    print(
        "Training Accuracy V2 model..."
    )

    classifier.fit(
        split["x_train"],
        split["y_train"],
        sample_weight=sample_weights(
            split["y_train"]
        ),
    )

    calibration_raw = (
        classifier.predict_proba(
            split[
                "x_calibration"
            ]
        )[:, 1]
    )

    calibrator = IsotonicRegression(
        y_min=0.0,
        y_max=1.0,
        out_of_bounds="clip",
    )

    calibrator.fit(
        calibration_raw,
        split[
            "y_calibration"
        ],
    )

    calibration_probabilities = (
        calibrator.predict(
            calibration_raw
        )
    )

    threshold = choose_threshold(
        split[
            "y_calibration"
        ],
        calibration_probabilities,
    )

    test_raw = (
        classifier.predict_proba(
            split["x_test"]
        )[:, 1]
    )

    test_probabilities = (
        calibrator.predict(
            test_raw
        )
    )

    evaluation = metrics(
        split["y_test"],
        test_probabilities,
        threshold,
    )

    trained_at = (
        datetime.now(
            timezone.utc
        ).isoformat()
    )

    model_version = (
        datetime.now(
            timezone.utc
        ).strftime(
            "accuracy-v2-%Y.%m.%d.%H%M%S"
        )
    )

    package = {
        "model": classifier,
        "probability_calibrator": (
            calibrator
        ),
        "feature_names": list(
            features.columns
        ),
        "model_type": type(
            classifier
        ).__name__,
        "model_version": (
            model_version
        ),
        "decision_threshold": float(
            threshold
        ),
        "trained_at": trained_at,
        "dataset_source": (
            "Kaggle malicious URL dataset "
            "plus Accuracy V2 hard negatives "
            "and brand-impersonation examples"
        ),
    }

    MODEL_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        package,
        MODEL_PATH,
    )

    metadata = {
        "model_version": (
            model_version
        ),
        "model_type": type(
            classifier
        ).__name__,
        "trained_at": trained_at,
        "dataset_records": int(
            len(dataset)
        ),
        "training_records": int(
            len(
                split["x_train"]
            )
        ),
        "calibration_records": int(
            len(
                split[
                    "x_calibration"
                ]
            )
        ),
        "testing_records": int(
            len(
                split["x_test"]
            )
        ),
        "hostname_overlap": int(
            len(overlap)
        ),
        "feature_count": int(
            len(
                features.columns
            )
        ),
        "feature_names": list(
            features.columns
        ),
        "decision_threshold": round(
            float(
                threshold
            ),
            6,
        ),
        "target_precision": (
            TARGET_PRECISION
        ),
        "metrics": evaluation,
    }

    METADATA_PATH.write_text(
        json.dumps(
            metadata,
            indent=2,
        ),
        encoding="utf-8",
    )

    EVALUATION_PATH.write_text(
        json.dumps(
            evaluation,
            indent=2,
        ),
        encoding="utf-8",
    )

    print()
    print(
        "=" * 65
    )
    print(
        "ACCURACY V2 TRAINING COMPLETE"
    )
    print(
        "=" * 65
    )
    print(
        "Threshold:",
        f"{threshold:.4f}",
    )
    print(
        "Accuracy:",
        evaluation["accuracy"],
    )
    print(
        "Precision:",
        evaluation["precision"],
    )
    print(
        "Recall:",
        evaluation["recall"],
    )
    print(
        "F1:",
        evaluation["f1_score"],
    )
    print(
        "False positives:",
        evaluation[
            "false_positives"
        ],
    )
    print(
        "False negatives:",
        evaluation[
            "false_negatives"
        ],
    )


if __name__ == "__main__":
    main()
