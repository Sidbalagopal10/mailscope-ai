from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from app.benchmarking.metrics import (
    classification_metrics,
)
from app.benchmarking.offline_detector import (
    analyze_offline,
)
from app.benchmarking.tranco_loader import (
    load_tranco_cases,
)
from app.benchmarking.urlhaus_loader import (
    load_urlhaus_cases,
)


OUTPUT = Path(
    "data/benchmarking/reports/"
    "latest_independent_benchmark.json"
)


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def predicted_malicious(
    score: float,
    threshold: float,
) -> bool:
    return bool(
        float(
            score
        )
        >= threshold
    )


def run(
    *,
    benign_limit: int,
    malicious_limit: int,
    threshold: float,
) -> dict:
    benign = load_tranco_cases(
        limit=benign_limit
    )

    malicious = load_urlhaus_cases(
        limit=malicious_limit
    )

    cases = [
        *benign,
        *malicious,
    ]

    tp = tn = fp = fn = 0

    failures = []
    results = []

    for index, case in enumerate(
        cases,
        start=1,
    ):
        result = analyze_offline(
            case.value
        )

        prediction = predicted_malicious(
            result[
                "risk_score"
            ],
            threshold,
        )

        expected = (
            case.expected_label
            == "malicious"
        )

        if expected and prediction:
            tp += 1

        elif (
            not expected
            and not prediction
        ):
            tn += 1

        elif (
            not expected
            and prediction
        ):
            fp += 1

        else:
            fn += 1

        row = {
            "value": case.value,
            "source": case.source,
            "expected": (
                case.expected_label
            ),
            "predicted_malicious": (
                prediction
            ),
            "result": result,
            "source_rank": (
                case.source_rank
            ),
        }

        results.append(
            row
        )

        if prediction != expected:
            failures.append(
                row
            )

        if index % 500 == 0:
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
        "generated_at": utc_now(),
        "benchmark_type": (
            "independent_offline_"
            "domain_url_benchmark"
        ),
        "real_world_accuracy_claim": False,
        "threshold": threshold,
        "benign_source": "Tranco",
        "malicious_source": "URLhaus",
        "benign_cases": len(
            benign
        ),
        "malicious_cases": len(
            malicious
        ),
        "metrics": metrics,
        "failure_count": len(
            failures
        ),
        "failures": failures[
            :500
        ],
        "results": results,
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


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--benign-limit",
        type=int,
        default=1000,
    )

    parser.add_argument(
        "--malicious-limit",
        type=int,
        default=1000,
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
        malicious_limit=(
            args.malicious_limit
        ),
        threshold=(
            args.threshold
        ),
    )

    print()
    print("=" * 70)
    print("INDEPENDENT BENCHMARK")
    print("=" * 70)

    print(
        "Benign:",
        report[
            "benign_cases"
        ],
    )

    print(
        "Malicious:",
        report[
            "malicious_cases"
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
        "Report:",
        OUTPUT,
    )


if __name__ == "__main__":
    main()
