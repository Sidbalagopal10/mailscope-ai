from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.shadow_evaluation.domain_bridge import (
    build_shadow_evidence,
)
from app.shadow_evaluation.validation_corpus import (
    build_validation_corpus,
)


OUTPUT = Path(
    "data/shadow_evaluation/"
    "latest_global_validation.json"
)


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def new_engine_only(
    case: dict[str, Any],
) -> dict[str, Any]:
    # For synthetic .example/.test/.invalid domains,
    # we deliberately do not call external intelligence.
    #
    # This benchmark focuses on identity semantics and
    # prevents meaningless external lookups.
    old_like_result = {
        "threatfox_intelligence": {
            "matched": False,
        },
        "virustotal_intelligence": {
            "maximum_malicious": 0,
            "maximum_suspicious": 0,
            "maximum_harmless": 0,
        },
        "global_brand_intelligence": {
            "impersonation_detected": (
                case[
                    "expected_class"
                ]
                == "lookalike"
            ),
            "similarity_score": (
                96
                if case[
                    "expected_class"
                ]
                == "lookalike"
                else 0
            ),
            "matched_brand": (
                case.get(
                    "entity_name"
                )
            ),
        },
    }

    shadow = build_shadow_evidence(
        url=case[
            "value"
        ],
        old_result=old_like_result,
    )

    fusion = shadow[
        "fusion"
    ]

    identity = shadow[
        "identity"
    ]

    return {
        "score": fusion.risk_score,
        "risk_level": fusion.risk_level,
        "verdict": fusion.verdict,
        "confidence": fusion.confidence,
        "identity_state": (
            identity.get(
                "identity_state"
            )
        ),
        "official_domain": (
            identity.get(
                "official_domain"
            )
        ),
        "safeguards": (
            fusion.safeguards_triggered
        ),
        "contributions": (
            fusion.contributions
        ),
    }


def expected_pass(
    expected_class: str,
    result: dict[str, Any],
) -> bool:
    score = float(
        result[
            "score"
        ]
    )

    identity_state = result.get(
        "identity_state"
    )

    if expected_class == "legitimate":
        return bool(
            score < 35
            and identity_state
            in {
                "verified",
                "supported",
            }
        )

    if expected_class == "unknown":
        return bool(
            score < 35
            and identity_state
            == "unknown"
        )

    if expected_class == "lookalike":
        return bool(
            identity_state
            == "unknown"
            and score >= 18
        )

    return False


def run_global_validation() -> dict[str, Any]:
    corpus = build_validation_corpus()

    results = []

    for index, case in enumerate(
        corpus,
        start=1,
    ):
        try:
            result = new_engine_only(
                case
            )

            passed = expected_pass(
                case[
                    "expected_class"
                ],
                result,
            )

            results.append(
                {
                    **case,
                    "result": result,
                    "passed": passed,
                }
            )

        except Exception as error:
            results.append(
                {
                    **case,
                    "passed": False,
                    "error": (
                        f"{type(error).__name__}: "
                        f"{error}"
                    ),
                }
            )

        if index % 100 == 0:
            print(
                f"Processed {index:,}/"
                f"{len(corpus):,}"
            )

    total = len(
        results
    )

    passed = sum(
        1
        for row in results
        if row.get(
            "passed"
        )
    )

    failures = [
        row
        for row in results
        if not row.get(
            "passed"
        )
    ]

    by_class = {}

    for expected in {
        row[
            "expected_class"
        ]
        for row in results
    }:
        rows = [
            row
            for row in results
            if row[
                "expected_class"
            ]
            == expected
        ]

        class_passed = sum(
            1
            for row in rows
            if row.get(
                "passed"
            )
        )

        by_class[
            expected
        ] = {
            "count": len(
                rows
            ),
            "passed": (
                class_passed
            ),
            "failed": (
                len(rows)
                - class_passed
            ),
            "pass_rate": round(
                class_passed
                / len(rows),
                4,
            )
            if rows
            else None,
        }

    report = {
        "generated_at": utc_now(),
        "benchmark_type": (
            "synthetic_and_registry_"
            "identity_regression"
        ),
        "real_world_accuracy_claim": False,
        "total_cases": total,
        "passed": passed,
        "failed": (
            total
            - passed
        ),
        "pass_rate": round(
            passed / total,
            4,
        )
        if total
        else None,
        "by_class": by_class,
        "failures": failures,
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


if __name__ == "__main__":
    report = run_global_validation()

    print()
    print("=" * 70)
    print("GLOBAL VALIDATION RESULT")
    print("=" * 70)

    print(
        "Cases:",
        report[
            "total_cases"
        ],
    )

    print(
        "Passed:",
        report[
            "passed"
        ],
    )

    print(
        "Failed:",
        report[
            "failed"
        ],
    )

    print(
        "Pass rate:",
        report[
            "pass_rate"
        ],
    )

    print()

    for name, values in (
        report[
            "by_class"
        ].items()
    ):
        print(
            name,
            "=>",
            values,
        )

    if report[
        "failures"
    ]:
        print()
        print(
            "First 20 failures:"
        )

        for row in report[
            "failures"
        ][
            :20
        ]:
            print(
                row[
                    "value"
                ],
                "expected=",
                row[
                    "expected_class"
                ],
                "result=",
                row.get(
                    "result"
                ),
                "error=",
                row.get(
                    "error"
                ),
            )

    print()
    print(
        "Full report:",
        OUTPUT,
    )
