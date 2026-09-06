import argparse
import json
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import pandas as pd


RAW_DIRECTORY = Path("training/raw")

OUTPUT_PATH = Path(
    "training/processed/phishing_url_dataset.csv"
)

METADATA_PATH = Path(
    "training/processed/dataset_metadata.json"
)

RANDOM_SEED = 42


def find_dataset_file() -> Path:
    preferred_names = [
        "malicious_phish.csv",
        "malicious_urls.csv",
    ]

    for filename in preferred_names:
        candidate = RAW_DIRECTORY / filename

        if candidate.exists():
            return candidate

    csv_files = list(
        RAW_DIRECTORY.rglob("*.csv")
    )

    if not csv_files:
        raise FileNotFoundError(
            "No CSV dataset was found in training/raw."
        )

    return max(
        csv_files,
        key=lambda path: path.stat().st_size,
    )


def resolve_column(
    columns,
    possible_names,
) -> Optional[str]:
    normalized = {
        str(column).strip().lower(): column
        for column in columns
    }

    for possible_name in possible_names:
        if possible_name.lower() in normalized:
            return normalized[possible_name.lower()]

    return None


def normalize_url(value: str) -> str:
    return str(value).strip()


def hostname_from_url(url: str) -> str:
    candidate = url.strip()

    if "://" not in candidate:
        candidate = f"http://{candidate}"

    try:
        parsed = urlparse(candidate)
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


def normalize_label(value: str) -> Optional[int]:
    label = str(value).strip().lower()

    benign_labels = {
        "benign",
        "good",
        "legitimate",
        "safe",
        "0",
    }

    phishing_labels = {
        "phishing",
        "phish",
        "1",
    }

    if label in benign_labels:
        return 0

    if label in phishing_labels:
        return 1

    return None


def sample_class(
    dataset: pd.DataFrame,
    label: int,
    maximum: Optional[int],
) -> pd.DataFrame:
    class_rows = dataset[
        dataset["label"] == label
    ]

    if (
        maximum is not None
        and len(class_rows) > maximum
    ):
        class_rows = class_rows.sample(
            n=maximum,
            random_state=RANDOM_SEED,
        )

    return class_rows


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare a binary benign-versus-phishing "
            "URL dataset."
        )
    )

    parser.add_argument(
        "--max-benign",
        type=int,
        default=200000,
        help="Maximum benign URLs. Use 0 for all.",
    )

    parser.add_argument(
        "--max-phishing",
        type=int,
        default=0,
        help="Maximum phishing URLs. Use 0 for all.",
    )

    arguments = parser.parse_args()

    dataset_path = find_dataset_file()

    print(f"Reading: {dataset_path}")

    raw_dataset = pd.read_csv(
        dataset_path,
        low_memory=False,
    )

    url_column = resolve_column(
        raw_dataset.columns,
        [
            "url",
            "website",
            "link",
            "domain",
        ],
    )

    label_column = resolve_column(
        raw_dataset.columns,
        [
            "type",
            "label",
            "class",
            "category",
            "status",
        ],
    )

    if url_column is None:
        raise ValueError(
            "Could not identify the URL column. "
            f"Available columns: {list(raw_dataset.columns)}"
        )

    if label_column is None:
        raise ValueError(
            "Could not identify the label column. "
            f"Available columns: {list(raw_dataset.columns)}"
        )

    dataset = raw_dataset[
        [
            url_column,
            label_column,
        ]
    ].copy()

    dataset.columns = [
        "url",
        "original_label",
    ]

    original_size = len(dataset)

    dataset = dataset.dropna(
        subset=[
            "url",
            "original_label",
        ]
    )

    dataset["url"] = dataset[
        "url"
    ].map(normalize_url)

    dataset["label"] = dataset[
        "original_label"
    ].map(normalize_label)

    excluded_classes = (
        dataset["label"].isna().sum()
    )

    dataset = dataset.dropna(
        subset=["label"]
    )

    dataset["label"] = dataset[
        "label"
    ].astype(int)

    dataset = dataset[
        dataset["url"].str.len().between(
            4,
            4096,
        )
    ]

    before_duplicates = len(dataset)

    dataset = dataset.drop_duplicates(
        subset=["url"],
        keep="first",
    )

    duplicate_count = (
        before_duplicates - len(dataset)
    )

    dataset["hostname"] = dataset[
        "url"
    ].map(hostname_from_url)

    dataset = dataset[
        dataset["hostname"].str.len() > 0
    ]

    maximum_benign = (
        arguments.max_benign
        if arguments.max_benign > 0
        else None
    )

    maximum_phishing = (
        arguments.max_phishing
        if arguments.max_phishing > 0
        else None
    )

    benign_rows = sample_class(
        dataset=dataset,
        label=0,
        maximum=maximum_benign,
    )

    phishing_rows = sample_class(
        dataset=dataset,
        label=1,
        maximum=maximum_phishing,
    )

    processed_dataset = pd.concat(
        [
            benign_rows,
            phishing_rows,
        ],
        ignore_index=True,
    )

    processed_dataset = processed_dataset.sample(
        frac=1,
        random_state=RANDOM_SEED,
    ).reset_index(drop=True)

    output_dataset = processed_dataset[
        [
            "url",
            "label",
            "hostname",
        ]
    ]

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_dataset.to_csv(
        OUTPUT_PATH,
        index=False,
    )

    label_counts = (
        output_dataset["label"]
        .value_counts()
        .sort_index()
        .to_dict()
    )

    metadata = {
        "raw_file": str(dataset_path),
        "processed_file": str(OUTPUT_PATH),
        "original_records": int(original_size),
        "processed_records": int(
            len(output_dataset)
        ),
        "benign_records": int(
            label_counts.get(0, 0)
        ),
        "phishing_records": int(
            label_counts.get(1, 0)
        ),
        "excluded_non_binary_records": int(
            excluded_classes
        ),
        "duplicates_removed": int(
            duplicate_count
        ),
        "random_seed": RANDOM_SEED,
    }

    METADATA_PATH.write_text(
        json.dumps(
            metadata,
            indent=2,
        ),
        encoding="utf-8",
    )

    print()
    print("=" * 65)
    print("DATASET PREPARATION COMPLETE")
    print("=" * 65)

    print(
        f"Processed records: "
        f"{len(output_dataset):,}"
    )

    print(
        f"Benign records: "
        f"{label_counts.get(0, 0):,}"
    )

    print(
        f"Phishing records: "
        f"{label_counts.get(1, 0):,}"
    )

    print(
        f"Unique hostnames: "
        f"{output_dataset['hostname'].nunique():,}"
    )

    print(
        f"Dataset saved to: {OUTPUT_PATH}"
    )

    print(
        f"Metadata saved to: {METADATA_PATH}"
    )


if __name__ == "__main__":
    main()
