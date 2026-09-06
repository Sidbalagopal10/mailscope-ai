from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.benchmarking.leakage_audit import (
    audit_cross_feed_overlap,
)
from app.benchmarking.metrics import (
    classification_metrics,
)
from app.benchmarking.offline_detector import (
    analyze_offline,
)
from app.benchmarking.openphish_loader import (
    load_openphish_cases,
)
from app.benchmarking.tranco_loader import (
    load_tranco_cases,
)


OUTPUT = Path(
    "data/benchmarking/reports/"
    "latest_openphish_holdout.json"
)


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def classify(
    score: float,
    threshold: float,
) -> bool:
    return bool(
        float(score)
        >= float(threshold)
    )


def metrics_from_rows(
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    tp = tn = fp = fn = 0

    for row in rows:
        expected = bool(
            row[
                "expected_malicious"
            ]
        )

        predicted = bool(
            row[
                "predicted_malicious"
            ]
        )

        if expected and predicted:
            tp += 1

        elif not expected and not predicted:
            tn += 1

        elif not expected and predicted:
            fp += 1

        else:
            fn += 1

    return classification_metrics(
        true_positive=tp,
        true_negative=tn,
        false_positive=fp,
        false_negative=fn,
    )


def evaluate_thresholds(
    rows: list[dict[str, Any]],
    thresholds: list[float],
) -> list[dict[str, Any]]:
    evaluations = []

    for threshold in thresholds:
        threshold_rows = []

        for original in rows:
            row = dict(
                original
            )

            row[
                "predicted_malicious"
            ] = classify(
                row[
                    "score"
                ],
                threshold,
            )

            threshold_rows.append(
                row
            )

        evaluations.append(
            {
                "threshold": threshold,
                "metrics": (
                    metrics_from_rows(
                        threshold_rows
                    )
                ),
            }
        )

    return evaluations


def run(
    *,
    benign_limit: int = 500,
    phishing_limit: int = 500,
    threshold: float = 35.0,
    refresh_openphish: bool = False,
) -> dict[str, Any]:
    benign_cases = load_tranco_cases(
        limit=benign_limit
    )

    phishing_cases = load_openphish_cases(
        limit=phishing_limit,
        force_refresh=refresh_openphish,
    )

    rows = []

    print(
        "Evaluating benign holdout..."
    )

    for index, case in enumerate(
        benign_cases,
        start=1,
    ):
        result = analyze_offline(
            case.value
        )

        rows.append(
            {
                "value": case.value,
                "source": case.source,
                "expected_label": "benign",
                "expected_malicious": False,
                "score": result[
                    "risk_score"
                ],
                "risk_level": result[
                    "risk_level"
                ],
                "identity_state": result[
                    "identity_state"
                ],
                "predicted_malicious": (
                    classify(
                        result[
                            "risk_score"
                        ],
                        threshold,
                    )
                ),
                "urlhaus_exact_overlap": (
                    False
                ),
                "result": result,
            }
        )

        if index % 250 == 0:
            print(
                f"Benign: {index:,}/"
                f"{len(benign_cases):,}"
            )

    print()
    print(
        "Evaluating OpenPhish holdout..."
    )

    for index, case in enumerate(
        phishing_cases,
        start=1,
    ):
        leakage = (
            audit_cross_feed_overlap(
                case.value
            )
        )

        # CRITICAL:
        #
        # OpenPhish is NOT passed into the detector.
        # analyze_offline() knows nothing about the
        # OpenPhish label.
        result = analyze_offline(
            case.value
        )

        rows.append(
            {
                "value": case.value,
                "source": case.source,
                "expected_label": (
                    "phishing"
                ),
                "expected_malicious": True,
                "score": result[
                    "risk_score"
                ],
                "risk_level": result[
                    "risk_level"
                ],
                "identity_state": result[
                    "identity_state"
                ],
                "predicted_malicious": (
                    classify(
                        result[
                            "risk_score"
                        ],
                        threshold,
                    )
                ),
                "urlhaus_exact_overlap": (
                    leakage[
                        "urlhaus_exact_overlap"
                    ]
                ),
                "result": result,
            }
        )

        if index % 100 == 0:
            print(
                f"OpenPhish: {index:,}/"
                f"{len(phishing_cases):,}"
            )

    all_metrics = metrics_from_rows(
        rows
    )

    benign_rows = [
        row
        for row in rows
        if not row[
            "expected_malicious"
        ]
    ]

    phishing_rows = [
        row
        for row in rows
        if row[
            "expected_malicious"
        ]
    ]

    phishing_no_urlhaus = [
        row
        for row in phishing_rows
        if not row[
            "urlhaus_exact_overlap"
        ]
    ]

    phishing_urlhaus_overlap = [
        row
        for row in phishing_rows
        if row[
            "urlhaus_exact_overlap"
        ]
    ]

    benign_fp = sum(
        1
        for row in benign_rows
        if row[
            "predicted_malicious"
        ]
    )

    phishing_detected = sum(
        1
        for row in phishing_rows
        if row[
            "predicted_malicious"
        ]
    )

    no_overlap_detected = sum(
        1
        for row in phishing_no_urlhaus
        if row[
            "predicted_malicious"
        ]
    )

    overlap_detected = sum(
        1
        for row in phishing_urlhaus_overlap
        if row[
            "predicted_malicious"
        ]
    )

    threshold_sweep = (
        evaluate_thresholds(
            rows,
            [
                15.0,
                20.0,
                25.0,
                30.0,
                35.0,
                40.0,
                50.0,
                60.0,
            ],
        )
    )

    report = {
        "generated_at": utc_now(),

        "benchmark_type": (
            "openphish_independent_holdout"
        ),

        "real_world_accuracy_claim": False,

        "ground_truth_source": (
            "OpenPhish Community Feed"
        ),

        "detector_uses_openphish": False,

        "current_threshold": threshold,

        "counts": {
            "benign": len(
                benign_rows
            ),
            "phishing": len(
                phishing_rows
            ),
            "phishing_urlhaus_overlap": len(
                phishing_urlhaus_overlap
            ),
            "phishing_without_urlhaus_overlap": len(
                phishing_no_urlhaus
            ),
        },

        "metrics": all_metrics,

        "benign_false_positive_rate": (
            round(
                benign_fp
                / len(
                    benign_rows
                ),
                4,
            )
            if benign_rows
            else 0.0
        ),

        "phishing_detection_rate": (
            round(
                phishing_detected
                / len(
                    phishing_rows
                ),
                4,
            )
            if phishing_rows
            else 0.0
        ),

        "phishing_detection_rate_without_urlhaus_overlap": (
            round(
                no_overlap_detected
                / len(
                    phishing_no_urlhaus
                ),
                4,
            )
            if phishing_no_urlhaus
            else None
        ),

        "urlhaus_overlap_detection_rate": (
            round(
                overlap_detected
                / len(
                    phishing_urlhaus_overlap
                ),
                4,
            )
            if phishing_urlhaus_overlap
            else None
        ),

        "threshold_sweep": (
            threshold_sweep
        ),

        "false_positives": [
            row
            for row in benign_rows
            if row[
                "predicted_malicious"
            ]
        ][
            :200
        ],

        "false_negatives_without_urlhaus_overlap": [
            row
            for row in phishing_no_urlhaus
            if not row[
                "predicted_malicious"
            ]
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


def main() -> None:
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

    parser.add_argument(
        "--refresh-openphish",
        action="store_true",
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
        refresh_openphish=(
            args.refresh_openphish
        ),
    )

    print()
    print("=" * 76)
    print(
        "OPENPHISH INDEPENDENT HOLDOUT"
    )
    print("=" * 76)

    print(
        "Detector uses OpenPhish:",
        report[
            "detector_uses_openphish"
        ],
    )

    print()
    print(
        "Counts:"
    )

    for key, value in report[
        "counts"
    ].items():
        print(
            f"  {key}: {value}"
        )

    print()
    print(
        "Current threshold:",
        report[
            "current_threshold"
        ],
    )

    print()
    print(
        "Overall metrics:"
    )

    for key, value in report[
        "metrics"
    ].items():
        print(
            f"  {key}: {value}"
        )

    print()
    print(
        "Benign FPR:",
        report[
            "benign_false_positive_rate"
        ],
    )

    print(
        "OpenPhish detection rate:",
        report[
            "phishing_detection_rate"
        ],
    )

    print(
        "OpenPhish detection rate "
        "WITHOUT URLhaus overlap:",
        report[
            "phishing_detection_rate_without_urlhaus_overlap"
        ],
    )

    print(
        "URLhaus-overlap detection rate:",
        report[
            "urlhaus_overlap_detection_rate"
        ],
    )

    print()
    print(
        "THRESHOLD SWEEP"
    )

    print(
        f"{'THRESHOLD':>10}"
        f"{'PRECISION':>12}"
        f"{'RECALL':>10}"
        f"{'F1':>10}"
        f"{'FPR':>10}"
        f"{'FNR':>10}"
    )

    print(
        "-" * 62
    )

    for item in report[
        "threshold_sweep"
    ]:
        metrics = item[
            "metrics"
        ]

        print(
            f"{item['threshold']:>10.1f}"
            f"{metrics['precision']:>12.4f}"
            f"{metrics['recall']:>10.4f}"
            f"{metrics['f1']:>10.4f}"
            f"{metrics['false_positive_rate']:>10.4f}"
            f"{metrics['false_negative_rate']:>10.4f}"
        )

    print()
    print(
        "Report:",
        OUTPUT,
    )


if __name__ == "__main__":
    main()
