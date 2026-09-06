from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from app.benchmarking.hosting_detector import (
    analyze_with_hosting,
)
from app.benchmarking.metrics import (
    classification_metrics,
)
from app.benchmarking.openphish_loader import (
    load_openphish_cases,
)
from app.benchmarking.tranco_loader import (
    load_tranco_cases,
)


OUTPUT = Path(
    "data/benchmarking/reports/"
    "latest_hosting_holdout.json"
)


def run(
    *,
    benign_limit: int = 500,
    phishing_limit: int = 500,
    threshold: float = 35.0,
):
    benign = load_tranco_cases(
        limit=benign_limit
    )

    phishing = load_openphish_cases(
        limit=phishing_limit
    )

    rows = []

    tp = tn = fp = fn = 0

    provider_counts = Counter()

    phishing_provider_counts = Counter()

    cases = [
        *benign,
        *phishing,
    ]

    for index, case in enumerate(
        cases,
        start=1,
    ):
        result = analyze_with_hosting(
            case.value
        )

        expected = (
            case.expected_label
            == "malicious"
        )

        predicted = (
            result[
                "risk_score"
            ]
            >= threshold
        )

        hosting = result.get(
            "hosting",
            {}
        )

        if hosting.get(
            "matched"
        ):
            provider_name = (
                str(
                    hosting.get(
                        "provider"
                    )
                )
                + " / "
                + str(
                    hosting.get(
                        "platform"
                    )
                )
            )

            provider_counts[
                provider_name
            ] += 1

            if expected:
                phishing_provider_counts[
                    provider_name
                ] += 1

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
                "expected": (
                    case.expected_label
                ),
                "predicted_malicious": (
                    predicted
                ),
                "result": result,
            }
        )

        if index % 100 == 0:
            print(
                f"Processed {index:,}/"
                f"{len(cases):,}"
            )

    metrics = classification_metrics(
        true_positive=tp,
        true_negative=tn,
        false_positive=fp,
        false_negative=fn,
    )

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

        "hosting_matches_total": sum(
            provider_counts.values()
        ),

        "hosting_matches_phishing": sum(
            phishing_provider_counts.values()
        ),

        "provider_counts": (
            provider_counts.most_common()
        ),

        "phishing_provider_counts": (
            phishing_provider_counts.most_common()
        ),

        "false_positives": [
            row
            for row in rows
            if (
                row[
                    "expected"
                ]
                == "benign"
                and row[
                    "predicted_malicious"
                ]
            )
        ],

        "false_negatives": [
            row
            for row in rows
            if (
                row[
                    "expected"
                ]
                == "malicious"
                and not row[
                    "predicted_malicious"
                ]
            )
        ][
            :200
        ],

        "results": rows,
    }

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

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
        default=500,
    )

    parser.add_argument(
        "--phishing-limit",
        type=int,
        default=500,
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=35.0,
    )

    args = parser.parse_args()

    report = run(
        benign_limit=(
            args.benign_limit
        ),
        phishing_limit=(
            args.phishing_limit
        ),
        threshold=(
            args.threshold
        ),
    )

    print()
    print("=" * 76)
    print(
        "HOSTING INTELLIGENCE HOLDOUT"
    )
    print("=" * 76)

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
        "Hosting matches:",
        report[
            "hosting_matches_total"
        ],
    )

    print(
        "Hosting matches among phishing:",
        report[
            "hosting_matches_phishing"
        ],
    )

    print()
    print(
        "Top phishing hosting platforms:"
    )

    for provider, count in report[
        "phishing_provider_counts"
    ][
        :20
    ]:
        print(
            f"  {provider}: {count}"
        )

    print()
    print(
        "Report:",
        OUTPUT,
    )
