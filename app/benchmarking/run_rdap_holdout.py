from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from app.benchmarking.metrics import (
    classification_metrics,
)
from app.benchmarking.openphish_loader import (
    load_openphish_cases,
)
from app.benchmarking.rdap_detector import (
    analyze_with_rdap,
)
from app.benchmarking.tranco_loader import (
    load_tranco_cases,
)


OUTPUT = Path(
    "data/benchmarking/reports/"
    "latest_rdap_holdout.json"
)


def run(
    benign_limit: int,
    phishing_limit: int,
    threshold: float,
):
    benign = load_tranco_cases(
        limit=benign_limit
    )

    phishing = load_openphish_cases(
        limit=phishing_limit
    )

    rows = []

    tp = tn = fp = fn = 0

    cases = [
        *benign,
        *phishing,
    ]

    for index, case in enumerate(
        cases,
        start=1,
    ):
        print(
            f"[{index}/{len(cases)}] "
            f"{case.value[:75]}"
        )

        result = analyze_with_rdap(
            case.value
        )

        predicted = (
            result[
                "risk_score"
            ]
            >= threshold
        )

        expected = (
            case.expected_label
            == "malicious"
        )

        if expected and predicted:
            tp += 1

        elif (
            not expected
            and not predicted
        ):
            tn += 1

        elif (
            not expected
            and predicted
        ):
            fp += 1

        else:
            fn += 1

        rows.append(
            {
                "value": case.value,
                "source": case.source,
                "expected": (
                    case.expected_label
                ),
                "predicted_malicious": (
                    predicted
                ),
                "result": result,
            }
        )

    metrics = classification_metrics(
        true_positive=tp,
        true_negative=tn,
        false_positive=fp,
        false_negative=fn,
    )

    age_buckets = {
        "0_3_days": 0,
        "4_14_days": 0,
        "15_60_days": 0,
        "61_365_days": 0,
        "366_3649_days": 0,
        "3650_plus_days": 0,
        "unknown": 0,
    }

    for row in rows:
        age = (
            row[
                "result"
            ]
            .get(
                "rdap",
                {}
            )
            .get(
                "domain_age_days"
            )
        )

        if age is None:
            age_buckets[
                "unknown"
            ] += 1

        elif age <= 3:
            age_buckets[
                "0_3_days"
            ] += 1

        elif age <= 14:
            age_buckets[
                "4_14_days"
            ] += 1

        elif age <= 60:
            age_buckets[
                "15_60_days"
            ] += 1

        elif age <= 365:
            age_buckets[
                "61_365_days"
            ] += 1

        elif age < 3650:
            age_buckets[
                "366_3649_days"
            ] += 1

        else:
            age_buckets[
                "3650_plus_days"
            ] += 1

    report = {
        "generated_at": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),
        "threshold": threshold,
        "benign_cases": len(
            benign
        ),
        "phishing_cases": len(
            phishing
        ),
        "metrics": metrics,
        "age_buckets": (
            age_buckets
        ),
        "results": rows,
    }

    OUTPUT.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
            default=str,
        ),
        encoding="utf-8",
    )

    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--benign-limit",
        type=int,
        default=50,
    )

    parser.add_argument(
        "--phishing-limit",
        type=int,
        default=50,
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=35.0,
    )

    args = parser.parse_args()

    report = run(
        args.benign_limit,
        args.phishing_limit,
        args.threshold,
    )

    print()
    print("=" * 70)
    print("RDAP HOLDOUT")
    print("=" * 70)

    print(
        "Benign:",
        report[
            "benign_cases"
        ],
    )

    print(
        "Phishing:",
        report[
            "phishing_cases"
        ],
    )

    print()

    for key, value in report[
        "metrics"
    ].items():
        print(
            key,
            "=",
            value,
        )

    print()
    print(
        "Age buckets:"
    )

    for key, value in report[
        "age_buckets"
    ].items():
        print(
            f"  {key}: {value}"
        )

    print()
    print(
        "Report:",
        OUTPUT,
    )
