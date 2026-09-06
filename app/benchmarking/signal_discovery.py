from __future__ import annotations

import json
import math
import statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.benchmarking.openphish_loader import (
    load_openphish_cases,
)
from app.benchmarking.structural_features import (
    extract_structural_features,
)
from app.benchmarking.tranco_loader import (
    load_tranco_cases,
)


OUTPUT = Path(
    "data/benchmarking/reports/"
    "latest_signal_discovery.json"
)


NUMERIC_FEATURES = [
    "url_length",
    "hostname_length",
    "hostname_entropy",
    "url_entropy",
    "label_count",
    "subdomain_depth",
    "longest_label_length",
    "digit_count",
    "digit_ratio",
    "alpha_ratio",
    "hyphen_count",
    "underscore_count",
    "query_parameter_count",
    "encoded_token_count",
    "sensitive_term_count",
    "brand_token_count",
    "hex_like_label_count",
    "path_length",
    "query_length",
]


BOOLEAN_FEATURES = [
    "contains_punycode",
    "hostname_is_ip",
    "contains_at_symbol",
    "repeated_separator",
    "non_standard_port",
    "uses_https",
]


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def percentile(
    values: list[float],
    fraction: float,
) -> float:
    if not values:
        return 0.0

    ordered = sorted(
        values
    )

    index = (
        len(ordered) - 1
    ) * fraction

    lower = math.floor(
        index
    )

    upper = math.ceil(
        index
    )

    if lower == upper:
        return float(
            ordered[
                int(index)
            ]
        )

    lower_value = ordered[
        lower
    ]

    upper_value = ordered[
        upper
    ]

    return float(
        lower_value
        + (
            upper_value
            - lower_value
        )
        * (
            index
            - lower
        )
    )


def numeric_summary(
    rows: list[dict[str, Any]],
    feature: str,
) -> dict[str, float]:
    values = [
        float(
            row.get(
                feature,
                0.0,
            )
            or 0.0
        )
        for row in rows
    ]

    if not values:
        return {}

    return {
        "mean": round(
            statistics.mean(
                values
            ),
            4,
        ),

        "median": round(
            statistics.median(
                values
            ),
            4,
        ),

        "p75": round(
            percentile(
                values,
                0.75,
            ),
            4,
        ),

        "p90": round(
            percentile(
                values,
                0.90,
            ),
            4,
        ),

        "p95": round(
            percentile(
                values,
                0.95,
            ),
            4,
        ),

        "max": round(
            max(
                values
            ),
            4,
        ),
    }


def boolean_rate(
    rows: list[dict[str, Any]],
    feature: str,
) -> float:
    if not rows:
        return 0.0

    count = sum(
        bool(
            row.get(
                feature,
                False,
            )
        )
        for row in rows
    )

    return round(
        count
        / len(
            rows
        ),
        4,
    )


def signal_separation(
    benign: list[dict[str, Any]],
    phishing: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    comparisons = []

    for feature in NUMERIC_FEATURES:
        benign_summary = (
            numeric_summary(
                benign,
                feature,
            )
        )

        phishing_summary = (
            numeric_summary(
                phishing,
                feature,
            )
        )

        benign_mean = float(
            benign_summary.get(
                "mean",
                0.0,
            )
        )

        phishing_mean = float(
            phishing_summary.get(
                "mean",
                0.0,
            )
        )

        difference = (
            phishing_mean
            - benign_mean
        )

        comparisons.append(
            {
                "feature": (
                    feature
                ),

                "type": (
                    "numeric"
                ),

                "benign": (
                    benign_summary
                ),

                "phishing": (
                    phishing_summary
                ),

                "mean_difference": round(
                    difference,
                    4,
                ),

                "absolute_mean_difference": round(
                    abs(
                        difference
                    ),
                    4,
                ),
            }
        )

    for feature in BOOLEAN_FEATURES:
        benign_value = (
            boolean_rate(
                benign,
                feature,
            )
        )

        phishing_value = (
            boolean_rate(
                phishing,
                feature,
            )
        )

        difference = (
            phishing_value
            - benign_value
        )

        comparisons.append(
            {
                "feature": (
                    feature
                ),

                "type": (
                    "boolean"
                ),

                "benign_rate": (
                    benign_value
                ),

                "phishing_rate": (
                    phishing_value
                ),

                "rate_difference": round(
                    difference,
                    4,
                ),

                "absolute_rate_difference": round(
                    abs(
                        difference
                    ),
                    4,
                ),
            }
        )

    comparisons.sort(
        key=lambda item: (
            item.get(
                "absolute_mean_difference",
                item.get(
                    "absolute_rate_difference",
                    0.0,
                ),
            )
        ),
        reverse=True,
    )

    return comparisons


def run(
    *,
    benign_limit: int = 500,
    phishing_limit: int = 500,
) -> dict[str, Any]:
    benign_cases = load_tranco_cases(
        limit=benign_limit
    )

    phishing_cases = (
        load_openphish_cases(
            limit=phishing_limit,
        )
    )

    benign_rows = []

    phishing_rows = []

    for case in benign_cases:
        features = (
            extract_structural_features(
                case.value
            )
        )

        if features:
            benign_rows.append(
                features
            )

    for case in phishing_cases:
        features = (
            extract_structural_features(
                case.value
            )
        )

        if features:
            phishing_rows.append(
                features
            )

    comparison = signal_separation(
        benign_rows,
        phishing_rows,
    )

    benign_terms = Counter()

    phishing_terms = Counter()

    benign_brands = Counter()

    phishing_brands = Counter()

    for row in benign_rows:
        benign_terms.update(
            row.get(
                "sensitive_terms",
                [],
            )
        )

        benign_brands.update(
            row.get(
                "brand_tokens",
                [],
            )
        )

    for row in phishing_rows:
        phishing_terms.update(
            row.get(
                "sensitive_terms",
                [],
            )
        )

        phishing_brands.update(
            row.get(
                "brand_tokens",
                [],
            )
        )

    report = {
        "generated_at": (
            utc_now()
        ),

        "benign_count": len(
            benign_rows
        ),

        "phishing_count": len(
            phishing_rows
        ),

        "signal_comparison": (
            comparison
        ),

        "benign_sensitive_terms": (
            benign_terms.most_common(
                25
            )
        ),

        "phishing_sensitive_terms": (
            phishing_terms.most_common(
                25
            )
        ),

        "benign_brand_tokens": (
            benign_brands.most_common(
                25
            )
        ),

        "phishing_brand_tokens": (
            phishing_brands.most_common(
                25
            )
        ),
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
        ),
        encoding="utf-8",
    )

    return report


if __name__ == "__main__":
    report = run()

    print()
    print("=" * 90)

    print(
        "STRUCTURAL PHISHING SIGNAL DISCOVERY"
    )

    print("=" * 90)

    print(
        "Benign:",
        report[
            "benign_count"
        ],
    )

    print(
        "Phishing:",
        report[
            "phishing_count"
        ],
    )

    print()
    print(
        f"{'FEATURE':<28}"
        f"{'BENIGN':>14}"
        f"{'PHISHING':>14}"
        f"{'DIFFERENCE':>14}"
    )

    print(
        "-" * 70
    )

    for item in report[
        "signal_comparison"
    ][
        :25
    ]:

        if (
            item[
                "type"
            ]
            == "numeric"
        ):
            print(
                f"{item['feature']:<28}"
                f"{item['benign']['mean']:>14.4f}"
                f"{item['phishing']['mean']:>14.4f}"
                f"{item['mean_difference']:>14.4f}"
            )

        else:
            print(
                f"{item['feature']:<28}"
                f"{item['benign_rate']:>14.4f}"
                f"{item['phishing_rate']:>14.4f}"
                f"{item['rate_difference']:>14.4f}"
            )

    print()
    print(
        "Phishing-sensitive terms:"
    )

    print(
        report[
            "phishing_sensitive_terms"
        ]
    )

    print()
    print(
        "Phishing brand tokens:"
    )

    print(
        report[
            "phishing_brand_tokens"
        ]
    )

    print()
    print(
        "Report:",
        OUTPUT,
    )
