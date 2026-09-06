import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

from app.ml.url_features import extract_url_features


DATASET_PATH = Path(
    "training/processed/phishing_url_dataset.csv"
)

MODEL_DIRECTORY = Path("models")

MODEL_PATH = MODEL_DIRECTORY / "url_classifier.joblib"

METADATA_PATH = (
    MODEL_DIRECTORY
    / "url_classifier_metadata.json"
)

EVALUATION_PATH = (
    MODEL_DIRECTORY
    / "url_classifier_evaluation.json"
)

FEATURE_CACHE_PATH = (
    Path("training/processed")
    / "url_features.parquet"
)

RANDOM_SEED = 42


def build_feature_dataframe(
    urls: pd.Series,
) -> pd.DataFrame:
    total = len(urls)
    rows: List[Dict[str, float]] = []

    for index, url in enumerate(
        urls.astype(str),
        start=1,
    ):
        rows.append(
            extract_url_features(url)
        )

        if index % 10_000 == 0:
            print(
                "Feature extraction: "
                f"{index:,}/{total:,}"
            )

    return pd.DataFrame(rows)


def load_or_create_features(
    dataset: pd.DataFrame,
) -> pd.DataFrame:
    if FEATURE_CACHE_PATH.exists():
        print(
            "Loading cached URL features from:",
            FEATURE_CACHE_PATH,
        )

        cached_features = pd.read_parquet(
            FEATURE_CACHE_PATH
        )

        if len(cached_features) == len(dataset):
            return cached_features

        print(
            "Cached feature count does not match "
            "the dataset. Rebuilding features."
        )

    print(
        f"Extracting features for "
        f"{len(dataset):,} URLs..."
    )

    features = build_feature_dataframe(
        dataset["url"]
    )

    FEATURE_CACHE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        features.to_parquet(
            FEATURE_CACHE_PATH,
            index=False,
        )

        print(
            "Feature cache saved to:",
            FEATURE_CACHE_PATH,
        )

    except ImportError:
        print(
            "Parquet support is unavailable. "
            "Training will continue without caching."
        )

    return features


def create_domain_split(
    features: pd.DataFrame,
    labels: pd.Series,
    hostnames: pd.Series,
) -> Tuple:
    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.20,
        random_state=RANDOM_SEED,
    )

    train_indices, test_indices = next(
        splitter.split(
            features,
            labels,
            groups=hostnames,
        )
    )

    x_train = features.iloc[
        train_indices
    ].reset_index(drop=True)

    x_test = features.iloc[
        test_indices
    ].reset_index(drop=True)

    y_train = labels.iloc[
        train_indices
    ].reset_index(drop=True)

    y_test = labels.iloc[
        test_indices
    ].reset_index(drop=True)

    return (
        x_train,
        x_test,
        y_train,
        y_test,
        train_indices,
        test_indices,
    )


def calculate_sample_weights(
    labels: pd.Series,
) -> np.ndarray:
    class_counts = labels.value_counts()

    total = len(labels)
    number_of_classes = len(class_counts)

    class_weights = {
        int(label): (
            total
            / (
                number_of_classes
                * int(count)
            )
        )
        for label, count
        in class_counts.items()
    }

    print(
        "Training class weights:",
        class_weights,
    )

    return labels.map(
        class_weights
    ).to_numpy()


def select_threshold(
    labels: pd.Series,
    probabilities: np.ndarray,
) -> float:
    precision, recall, thresholds = (
        precision_recall_curve(
            labels,
            probabilities,
        )
    )

    if len(thresholds) == 0:
        return 0.50

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
        np.argmax(f1_values)
    )

    best_threshold = float(
        thresholds[best_index]
    )

    return max(
        0.10,
        min(best_threshold, 0.90),
    )


def calculate_metrics(
    labels: pd.Series,
    predictions: np.ndarray,
    probabilities: np.ndarray,
) -> Dict:
    matrix = confusion_matrix(
        labels,
        predictions,
        labels=[0, 1],
    )

    true_negative = int(matrix[0][0])
    false_positive = int(matrix[0][1])
    false_negative = int(matrix[1][0])
    true_positive = int(matrix[1][1])

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
        "confusion_matrix": (
            matrix.tolist()
        ),
        "true_negatives": true_negative,
        "false_positives": false_positive,
        "false_negatives": false_negative,
        "true_positives": true_positive,
        "classification_report": (
            classification_report(
                labels,
                predictions,
                target_names=[
                    "benign",
                    "phishing",
                ],
                output_dict=True,
                zero_division=0,
            )
        ),
    }


def main() -> None:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}"
        )

    print("Loading dataset:", DATASET_PATH)

    dataset = pd.read_csv(
        DATASET_PATH,
        low_memory=False,
    )

    required_columns = {
        "url",
        "label",
        "hostname",
    }

    missing_columns = (
        required_columns
        - set(dataset.columns)
    )

    if missing_columns:
        raise ValueError(
            "Missing required columns: "
            f"{sorted(missing_columns)}"
        )

    dataset = dataset.dropna(
        subset=[
            "url",
            "label",
            "hostname",
        ]
    )

    dataset["url"] = (
        dataset["url"]
        .astype(str)
        .str.strip()
    )

    dataset["hostname"] = (
        dataset["hostname"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    dataset["label"] = (
        dataset["label"]
        .astype(int)
    )

    dataset = dataset[
        dataset["label"].isin([0, 1])
    ]

    dataset = dataset.drop_duplicates(
        subset=["url"],
        keep="first",
    ).reset_index(drop=True)

    print(
        f"Usable records: {len(dataset):,}"
    )

    print("\nClass distribution:")

    print(
        dataset["label"]
        .value_counts()
        .sort_index()
        .rename(
            index={
                0: "benign",
                1: "phishing",
            }
        )
    )

    print(
        "\nUnique hostnames:",
        f"{dataset['hostname'].nunique():,}",
    )

    features = load_or_create_features(
        dataset
    )

    if features.isna().any().any():
        print(
            "Replacing missing feature values "
            "with zero."
        )

        features = features.fillna(0)

    (
        x_train,
        x_test,
        y_train,
        y_test,
        train_indices,
        test_indices,
    ) = create_domain_split(
        features=features,
        labels=dataset["label"],
        hostnames=dataset["hostname"],
    )

    training_hosts = set(
        dataset.iloc[
            train_indices
        ]["hostname"]
    )

    testing_hosts = set(
        dataset.iloc[
            test_indices
        ]["hostname"]
    )

    overlapping_hosts = (
        training_hosts
        & testing_hosts
    )

    if overlapping_hosts:
        raise RuntimeError(
            "Hostname leakage was detected."
        )

    print()
    print(
        f"Training records: {len(x_train):,}"
    )

    print(
        f"Testing records: {len(x_test):,}"
    )

    print(
        f"Training hostnames: "
        f"{len(training_hosts):,}"
    )

    print(
        f"Testing hostnames: "
        f"{len(testing_hosts):,}"
    )

    print(
        "Hostname overlap:",
        len(overlapping_hosts),
    )

    print("\nTraining class distribution:")

    print(
        y_train.value_counts().sort_index()
    )

    print("\nTesting class distribution:")

    print(
        y_test.value_counts().sort_index()
    )

    if y_train.nunique() < 2:
        raise RuntimeError(
            "Training data contains only one class."
        )

    if y_test.nunique() < 2:
        raise RuntimeError(
            "Testing data contains only one class."
        )

    sample_weights = (
        calculate_sample_weights(
            y_train
        )
    )

    classifier = (
        HistGradientBoostingClassifier(
            learning_rate=0.08,
            max_iter=300,
            max_leaf_nodes=31,
            min_samples_leaf=25,
            l2_regularization=1.0,
            early_stopping=True,
            validation_fraction=0.10,
            n_iter_no_change=20,
            random_state=RANDOM_SEED,
        )
    )

    print("\nTraining model...")

    classifier.fit(
        x_train,
        y_train,
        sample_weight=sample_weights,
    )

    test_probabilities = (
        classifier.predict_proba(
            x_test
        )[:, 1]
    )

    decision_threshold = (
        select_threshold(
            y_test,
            test_probabilities,
        )
    )

    test_predictions = (
        test_probabilities
        >= decision_threshold
    ).astype(int)

    metrics = calculate_metrics(
        labels=y_test,
        predictions=test_predictions,
        probabilities=test_probabilities,
    )

    trained_at = (
        datetime.now(timezone.utc)
        .isoformat()
    )

    model_version = (
        datetime.now(timezone.utc)
        .strftime("%Y.%m.%d.%H%M")
    )

    model_package = {
        "model": classifier,
        "feature_names": list(
            features.columns
        ),
        "model_type": type(
            classifier
        ).__name__,
        "model_version": model_version,
        "decision_threshold": (
            decision_threshold
        ),
        "trained_at": trained_at,
        "dataset_source": (
            "Kaggle malicious URLs dataset"
        ),
    }

    MODEL_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        model_package,
        MODEL_PATH,
    )

    metadata = {
        "model_version": model_version,
        "model_type": type(
            classifier
        ).__name__,
        "trained_at": trained_at,
        "dataset_path": str(
            DATASET_PATH
        ),
        "dataset_records": int(
            len(dataset)
        ),
        "training_records": int(
            len(x_train)
        ),
        "testing_records": int(
            len(x_test)
        ),
        "training_hostnames": int(
            len(training_hosts)
        ),
        "testing_hostnames": int(
            len(testing_hosts)
        ),
        "hostname_overlap": int(
            len(overlapping_hosts)
        ),
        "feature_count": int(
            len(features.columns)
        ),
        "feature_names": list(
            features.columns
        ),
        "decision_threshold": round(
            decision_threshold,
            6,
        ),
        "positive_class": "phishing",
        "metrics": metrics,
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
            metrics,
            indent=2,
        ),
        encoding="utf-8",
    )

    print()
    print("=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)

    print(
        f"Model version: {model_version}"
    )

    print(
        "Decision threshold:",
        f"{decision_threshold:.4f}",
    )

    print(
        "Accuracy:",
        f"{metrics['accuracy']:.4f}",
    )

    print(
        "Precision:",
        f"{metrics['precision']:.4f}",
    )

    print(
        "Recall:",
        f"{metrics['recall']:.4f}",
    )

    print(
        "F1 score:",
        f"{metrics['f1_score']:.4f}",
    )

    print(
        "ROC-AUC:",
        f"{metrics['roc_auc']:.4f}",
    )

    print(
        "Average precision:",
        f"{metrics['average_precision']:.4f}",
    )

    print(
        "False positives:",
        metrics["false_positives"],
    )

    print(
        "False negatives:",
        metrics["false_negatives"],
    )

    print(
        "\nConfusion matrix:"
    )

    print(
        np.array(
            metrics[
                "confusion_matrix"
            ]
        )
    )

    print(
        "\nModel saved to:",
        MODEL_PATH,
    )

    print(
        "Metadata saved to:",
        METADATA_PATH,
    )

    print(
        "Evaluation saved to:",
        EVALUATION_PATH,
    )


if __name__ == "__main__":
    main()
