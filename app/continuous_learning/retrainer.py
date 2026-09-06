from __future__ import annotations

import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GroupShuffleSplit

from app.ml.classifier import reload_url_classifier
from app.ml.url_features import extract_url_features


BASE_DATASET_PATH = Path(
    "training/processed/phishing_url_dataset.csv"
)

FEATURE_CACHE_PATH = Path(
    "training/processed/url_features.parquet"
)

FEEDBACK_DATABASE_PATH = Path(
    "data/feedback.db"
)

CURRENT_MODEL_PATH = Path(
    "models/url_classifier.joblib"
)

CANDIDATE_DIRECTORY = Path(
    "models/candidates"
)

ARCHIVE_DIRECTORY = Path(
    "models/archive"
)

REPORT_PATH = Path(
    "models/continuous_learning_report.json"
)

STATE_PATH = Path(
    "data/continuous_learning_state.json"
)

RANDOM_SEED = 42
MINIMUM_FEEDBACK = 25


class ContinuousLearningError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def hostname_from_url(
    url: str,
) -> str:
    candidate = str(url).strip()

    if "://" not in candidate:
        candidate = (
            f"http://{candidate}"
        )

    try:
        parsed = urlparse(
            candidate
        )

        return (
            parsed.hostname
            or "unknown"
        ).lower()

    except ValueError:
        return "unknown"


def load_feedback() -> pd.DataFrame:
    columns = [
        "url",
        "label",
        "hostname",
        "created_at",
    ]

    if not FEEDBACK_DATABASE_PATH.exists():
        return pd.DataFrame(
            columns=columns
        )

    with sqlite3.connect(
        FEEDBACK_DATABASE_PATH
    ) as connection:
        table = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'url_feedback'
            """
        ).fetchone()

        if not table:
            return pd.DataFrame(
                columns=columns
            )

        feedback = pd.read_sql_query(
            """
            SELECT
                url,
                confirmed_label AS label,
                created_at
            FROM url_feedback
            WHERE confirmed_label IN (0, 1)
              AND url IS NOT NULL
              AND TRIM(url) != ''
            ORDER BY id ASC
            """,
            connection,
        )

    if feedback.empty:
        return pd.DataFrame(
            columns=columns
        )

    feedback["url"] = (
        feedback["url"]
        .astype(str)
        .str.strip()
    )

    feedback["label"] = (
        feedback["label"]
        .astype(int)
    )

    feedback = feedback.drop_duplicates(
        subset=["url"],
        keep="last",
    )

    feedback["hostname"] = (
        feedback["url"]
        .map(hostname_from_url)
    )

    return feedback.reset_index(
        drop=True
    )


def read_json_file(
    path: Path,
) -> dict[str, Any]:
    if not path.exists():
        return {}

    try:
        return json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except json.JSONDecodeError:
        return {}


def get_learning_status() -> dict[str, Any]:
    feedback = load_feedback()
    state = read_json_file(
        STATE_PATH
    )
    report = read_json_file(
        REPORT_PATH
    )

    latest_feedback_at = None

    if (
        not feedback.empty
        and feedback[
            "created_at"
        ].notna().any()
    ):
        latest_feedback_at = (
            feedback["created_at"]
            .dropna()
            .max()
        )

    return {
        "verified_feedback_count": int(
            len(feedback)
        ),
        "minimum_feedback_required": (
            MINIMUM_FEEDBACK
        ),
        "ready_for_retraining": (
            len(feedback)
            >= MINIMUM_FEEDBACK
        ),
        "latest_feedback_at": (
            latest_feedback_at
        ),
        "last_attempt_at": state.get(
            "last_attempt_at"
        ),
        "last_feedback_count": state.get(
            "last_feedback_count",
            0,
        ),
        "last_result": state.get(
            "last_result"
        ),
        "last_promoted_at": state.get(
            "last_promoted_at"
        ),
        "latest_report": report,
    }


def load_base_dataset() -> pd.DataFrame:
    if not BASE_DATASET_PATH.exists():
        raise ContinuousLearningError(
            "Processed Kaggle dataset not found at "
            f"{BASE_DATASET_PATH}."
        )

    dataset = pd.read_csv(
        BASE_DATASET_PATH,
        low_memory=False,
    )

    required = {
        "url",
        "label",
        "hostname",
    }

    missing = (
        required
        - set(dataset.columns)
    )

    if missing:
        raise ContinuousLearningError(
            "Dataset is missing columns: "
            f"{sorted(missing)}"
        )

    dataset = dataset[
        [
            "url",
            "label",
            "hostname",
        ]
    ].dropna()

    dataset["url"] = (
        dataset["url"]
        .astype(str)
        .str.strip()
    )

    dataset["hostname"] = (
        dataset["hostname"]
        .astype(str)
        .str.lower()
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

    return dataset.drop_duplicates(
        subset=["url"],
        keep="first",
    ).reset_index(
        drop=True
    )


def load_or_build_features(
    dataset: pd.DataFrame,
) -> pd.DataFrame:
    if FEATURE_CACHE_PATH.exists():
        cached = pd.read_parquet(
            FEATURE_CACHE_PATH
        )

        if len(cached) == len(
            dataset
        ):
            return cached.reset_index(
                drop=True
            )

    rows = []

    for index, url in enumerate(
        dataset["url"].astype(str),
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
                f"{index:,}/"
                f"{len(dataset):,}",
            )

    features = pd.DataFrame(
        rows
    )

    FEATURE_CACHE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    features.to_parquet(
        FEATURE_CACHE_PATH,
        index=False,
    )

    return features


def calculate_sample_weights(
    labels: pd.Series,
) -> np.ndarray:
    counts = labels.value_counts()

    total = len(labels)
    class_count = len(counts)

    class_weights = {
        int(label): (
            total
            / (
                class_count
                * int(count)
            )
        )
        for label, count
        in counts.items()
    }

    return labels.map(
        class_weights
    ).to_numpy()


def calculate_metrics(
    labels: pd.Series,
    probabilities: np.ndarray,
    threshold: float,
) -> dict[str, Any]:
    predictions = (
        probabilities >= threshold
    ).astype(int)

    matrix = confusion_matrix(
        labels,
        predictions,
        labels=[0, 1],
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


def save_state(
    values: dict[str, Any],
) -> None:
    STATE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    current = read_json_file(
        STATE_PATH
    )

    current.update(
        values
    )

    STATE_PATH.write_text(
        json.dumps(
            current,
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )


def retrain_candidate(
    *,
    force: bool = False,
) -> dict[str, Any]:
    attempt_time = utc_now()
    feedback = load_feedback()
    status = get_learning_status()

    if (
        not force
        and len(feedback)
        < MINIMUM_FEEDBACK
    ):
        result = {
            "status": "skipped",
            "reason": (
                "Not enough verified feedback."
            ),
            "verified_feedback_count": int(
                len(feedback)
            ),
            "minimum_required": (
                MINIMUM_FEEDBACK
            ),
            "attempted_at": attempt_time,
        }

        save_state(
            {
                "last_attempt_at": (
                    attempt_time
                ),
                "last_feedback_count": int(
                    len(feedback)
                ),
                "last_result": result,
            }
        )

        return result

    if (
        not force
        and int(
            status.get(
                "last_feedback_count",
                0,
            )
        )
        >= len(feedback)
    ):
        result = {
            "status": "skipped",
            "reason": (
                "No new verified feedback "
                "since the last attempt."
            ),
            "verified_feedback_count": int(
                len(feedback)
            ),
            "attempted_at": attempt_time,
        }

        save_state(
            {
                "last_attempt_at": (
                    attempt_time
                ),
                "last_result": result,
            }
        )

        return result

    if not CURRENT_MODEL_PATH.exists():
        raise ContinuousLearningError(
            "Current model does not exist."
        )

    base_dataset = (
        load_base_dataset()
    )

    base_features = (
        load_or_build_features(
            base_dataset
        )
    )

    feedback_urls = set(
        feedback["url"]
    )

    keep_mask = ~base_dataset[
        "url"
    ].isin(
        feedback_urls
    )

    base_dataset = base_dataset[
        keep_mask
    ].reset_index(
        drop=True
    )

    base_features = base_features[
        keep_mask.to_numpy()
    ].reset_index(
        drop=True
    )

    feedback_features = pd.DataFrame(
        [
            extract_url_features(
                url
            )
            for url in feedback[
                "url"
            ].astype(str)
        ]
    )

    combined_dataset = pd.concat(
        [
            base_dataset,
            feedback[
                [
                    "url",
                    "label",
                    "hostname",
                ]
            ],
        ],
        ignore_index=True,
    )

    combined_features = pd.concat(
        [
            base_features,
            feedback_features,
        ],
        ignore_index=True,
    ).fillna(0)

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.20,
        random_state=RANDOM_SEED,
    )

    train_indices, test_indices = next(
        splitter.split(
            combined_features,
            combined_dataset[
                "label"
            ],
            groups=combined_dataset[
                "hostname"
            ],
        )
    )

    x_train = combined_features.iloc[
        train_indices
    ].reset_index(
        drop=True
    )

    x_test = combined_features.iloc[
        test_indices
    ].reset_index(
        drop=True
    )

    y_train = combined_dataset[
        "label"
    ].iloc[
        train_indices
    ].reset_index(
        drop=True
    )

    y_test = combined_dataset[
        "label"
    ].iloc[
        test_indices
    ].reset_index(
        drop=True
    )

    if (
        y_train.nunique() < 2
        or y_test.nunique() < 2
    ):
        raise ContinuousLearningError(
            "Train/test split must contain "
            "both benign and phishing classes."
        )

    candidate = (
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

    candidate.fit(
        x_train,
        y_train,
        sample_weight=(
            calculate_sample_weights(
                y_train
            )
        ),
    )

    current_package = joblib.load(
        CURRENT_MODEL_PATH
    )

    current_model = current_package[
        "model"
    ]

    feature_names = list(
        combined_features.columns
    )

    current_features = list(
        current_package[
            "feature_names"
        ]
    )

    if current_features != feature_names:
        raise ContinuousLearningError(
            "Current model feature order "
            "does not match current extractor."
        )

    current_threshold = float(
        current_package.get(
            "decision_threshold",
            0.50,
        )
    )

    candidate_threshold = 0.50

    current_probabilities = (
        current_model.predict_proba(
            x_test[
                current_features
            ]
        )[:, 1]
    )

    candidate_probabilities = (
        candidate.predict_proba(
            x_test[
                feature_names
            ]
        )[:, 1]
    )

    current_metrics = (
        calculate_metrics(
            y_test,
            current_probabilities,
            current_threshold,
        )
    )

    candidate_metrics = (
        calculate_metrics(
            y_test,
            candidate_probabilities,
            candidate_threshold,
        )
    )

    promotion_checks = {
        "recall_not_worse": (
            candidate_metrics["recall"]
            >= current_metrics["recall"]
            - 0.005
        ),
        "f1_not_worse": (
            candidate_metrics["f1_score"]
            >= current_metrics["f1_score"]
            - 0.002
        ),
        "false_negatives_not_worse": (
            candidate_metrics[
                "false_negatives"
            ]
            <= current_metrics[
                "false_negatives"
            ]
        ),
        "accuracy_not_collapsed": (
            candidate_metrics["accuracy"]
            >= current_metrics["accuracy"]
            - 0.01
        ),
    }

    promoted = all(
        promotion_checks.values()
    )

    trained_at = utc_now()

    model_version = (
        datetime.now(
            timezone.utc
        ).strftime(
            "feedback-%Y.%m.%d.%H%M%S"
        )
    )

    package = {
        "model": candidate,
        "feature_names": (
            feature_names
        ),
        "model_type": type(
            candidate
        ).__name__,
        "model_version": (
            model_version
        ),
        "decision_threshold": (
            candidate_threshold
        ),
        "trained_at": trained_at,
        "dataset_source": (
            "Kaggle dataset plus "
            "human-verified feedback"
        ),
        "verified_feedback_count": int(
            len(feedback)
        ),
    }

    CANDIDATE_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    candidate_path = (
        CANDIDATE_DIRECTORY
        / f"{model_version}.joblib"
    )

    joblib.dump(
        package,
        candidate_path,
    )

    archive_path = None

    if promoted:
        ARCHIVE_DIRECTORY.mkdir(
            parents=True,
            exist_ok=True,
        )

        current_version = str(
            current_package.get(
                "model_version",
                "unknown",
            )
        ).replace(
            "/",
            "_",
        )

        archive_path = (
            ARCHIVE_DIRECTORY
            / (
                f"{current_version}-"
                f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
                ".joblib"
            )
        )

        shutil.copy2(
            CURRENT_MODEL_PATH,
            archive_path,
        )

        shutil.copy2(
            candidate_path,
            CURRENT_MODEL_PATH,
        )

        reload_url_classifier()

    report = {
        "status": (
            "promoted"
            if promoted
            else "rejected"
        ),
        "attempted_at": (
            attempt_time
        ),
        "trained_at": trained_at,
        "model_version": (
            model_version
        ),
        "verified_feedback_count": int(
            len(feedback)
        ),
        "training_records": int(
            len(x_train)
        ),
        "testing_records": int(
            len(x_test)
        ),
        "current_metrics": (
            current_metrics
        ),
        "candidate_metrics": (
            candidate_metrics
        ),
        "promotion_checks": (
            promotion_checks
        ),
        "candidate_path": str(
            candidate_path
        ),
        "archive_path": (
            str(archive_path)
            if archive_path
            else None
        ),
    }

    REPORT_PATH.write_text(
        json.dumps(
            report,
            indent=2,
        ),
        encoding="utf-8",
    )

    state_values = {
        "last_attempt_at": (
            attempt_time
        ),
        "last_feedback_count": int(
            len(feedback)
        ),
        "last_result": report,
    }

    if promoted:
        state_values[
            "last_promoted_at"
        ] = trained_at

    save_state(
        state_values
    )

    return report
