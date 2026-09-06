from __future__ import annotations

import csv
import json
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.evidence_fusion.identity_aware_policy import (
    evaluate_identity_aware_candidate,
)
from app.global_entity_registry.database import (
    using_database,
)
from app.global_entity_registry.identity.shadow import (
    shadow_identity_summary,
)
from app.global_entity_registry.identity.live_detector_adapter import (
    run_live_detector,
)


REHEARSAL_DB = Path(
    "data/rehearsal/"
    "clean_registry_rehearsal.db"
)

TRANCO_ZIP = Path(
    "data/benchmarking/benign/"
    "tranco_top1m.csv.zip"
)

OPENPHISH = Path(
    "data/benchmarking/phishing/"
    "openphish_community_feed.txt"
)

REPORT = Path(
    "data/benchmarking/reports/"
    "final_core_identity_holdout.json"
)


def load_tranco(
    limit: int = 500,
) -> list[str]:
    if not TRANCO_ZIP.exists():
        raise FileNotFoundError(
            TRANCO_ZIP
        )

    urls: list[str] = []

    with zipfile.ZipFile(
        TRANCO_ZIP
    ) as archive:
        names = archive.namelist()

        if not names:
            raise RuntimeError(
                "Tranco ZIP is empty."
            )

        with archive.open(
            names[0]
        ) as handle:
            text = (
                line.decode(
                    "utf-8",
                    errors="ignore",
                )
                for line in handle
            )

            reader = csv.reader(
                text
            )

            for row in reader:
                if len(row) < 2:
                    continue

                domain = (
                    row[1]
                    .strip()
                    .lower()
                )

                if not domain:
                    continue

                urls.append(
                    "https://"
                    + domain
                    + "/"
                )

                if len(
                    urls
                ) >= limit:
                    break

    return urls


def load_openphish(
    limit: int = 500,
) -> list[str]:
    if not OPENPHISH.exists():
        raise FileNotFoundError(
            OPENPHISH
        )

    urls = []

    seen = set()

    for line in OPENPHISH.read_text(
        encoding="utf-8",
        errors="ignore",
    ).splitlines():
        value = line.strip()

        if not value:
            continue

        if value.startswith(
            "#"
        ):
            continue

        if value in seen:
            continue

        seen.add(
            value
        )

        urls.append(
            value
        )

        if len(
            urls
        ) >= limit:
            break

    return urls


def classify_old(
    result: dict[str, Any],
) -> bool:
    return bool(
        result.get(
            "is_suspicious"
        )
    )


def run_candidate(
    url: str,
    old: dict[str, Any],
) -> dict[str, Any]:
    with using_database(
        REHEARSAL_DB
    ):
        identity = (
            shadow_identity_summary(
                url
            )
        )

    decision = (
        evaluate_identity_aware_candidate(
            url=url,

            severity=float(
                old.get(
                    "severity"
                )
                or 0.0
            ),

            is_suspicious=bool(
                old.get(
                    "is_suspicious"
                )
            ),

            legacy_reasons=(
                old.get(
                    "reasons"
                )
                or []
            ),

            identity_state=(
                identity.get(
                    "identity_state",
                    "unknown",
                )
            ),
        )
    )

    return {
        "is_suspicious": (
            decision.candidate_suspicious
        ),

        "severity": (
            decision.candidate_severity
        ),

        "escalation_applied": (
            decision.escalation_applied
        ),

        "identity_state": (
            identity.get(
                "identity_state"
            )
        ),

        "identity_confidence": (
            identity.get(
                "identity_confidence"
            )
        ),

        "organization": (
            identity.get(
                "organization"
            )
        ),
    }


def metrics(
    *,
    benign_predictions: list[bool],
    phishing_predictions: list[bool],
) -> dict[str, Any]:
    fp = sum(
        benign_predictions
    )

    tn = (
        len(
            benign_predictions
        )
        - fp
    )

    tp = sum(
        phishing_predictions
    )

    fn = (
        len(
            phishing_predictions
        )
        - tp
    )

    precision = (
        tp
        / (
            tp + fp
        )
        if (
            tp + fp
        )
        else 0.0
    )

    recall = (
        tp
        / (
            tp + fn
        )
        if (
            tp + fn
        )
        else 0.0
    )

    specificity = (
        tn
        / (
            tn + fp
        )
        if (
            tn + fp
        )
        else 0.0
    )

    f1 = (
        (
            2
            * precision
            * recall
        )
        / (
            precision
            + recall
        )
        if (
            precision
            + recall
        )
        else 0.0
    )

    accuracy = (
        (
            tp + tn
        )
        / (
            tp
            + tn
            + fp
            + fn
        )
    )

    return {
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,

        "accuracy": round(
            accuracy,
            4,
        ),

        "precision": round(
            precision,
            4,
        ),

        "recall": round(
            recall,
            4,
        ),

        "specificity": round(
            specificity,
            4,
        ),

        "f1": round(
            f1,
            4,
        ),

        "false_positive_rate": round(
            (
                fp
                / (
                    fp + tn
                )
            )
            if (
                fp + tn
            )
            else 0.0,
            4,
        ),

        "false_negative_rate": round(
            (
                fn
                / (
                    fn + tp
                )
            )
            if (
                fn + tp
            )
            else 0.0,
            4,
        ),
    }


def evaluate(
    *,
    benign_limit: int = 500,
    phishing_limit: int = 500,
) -> dict[str, Any]:
    benign = load_tranco(
        benign_limit
    )

    phishing = load_openphish(
        phishing_limit
    )

    print(
        "Benign URLs:",
        len(
            benign
        ),
    )

    print(
        "Phishing URLs:",
        len(
            phishing
        ),
    )

    old_benign = []
    new_benign = []

    old_phishing = []
    new_phishing = []

    escalations = []

    errors = []

    print()
    print(
        "Evaluating benign..."
    )

    for index, url in enumerate(
        benign,
        start=1,
    ):
        try:
            old = run_live_detector(
                url
            )

            candidate = run_candidate(
                url,
                old,
            )

            old_benign.append(
                classify_old(
                    old
                )
            )

            new_benign.append(
                bool(
                    candidate[
                        "is_suspicious"
                    ]
                )
            )

            if candidate[
                "escalation_applied"
            ]:
                escalations.append(
                    {
                        "label": "benign",
                        "url": url,
                        "old": old,
                        "candidate": (
                            candidate
                        ),
                    }
                )

        except Exception as error:
            errors.append(
                {
                    "label": "benign",
                    "url": url,
                    "error": (
                        f"{type(error).__name__}: "
                        f"{error}"
                    ),
                }
            )

        if (
            index % 100
            == 0
        ):
            print(
                f"Benign: "
                f"{index}/"
                f"{len(benign)}"
            )

    print()
    print(
        "Evaluating phishing..."
    )

    for index, url in enumerate(
        phishing,
        start=1,
    ):
        try:
            old = run_live_detector(
                url
            )

            candidate = run_candidate(
                url,
                old,
            )

            old_phishing.append(
                classify_old(
                    old
                )
            )

            new_phishing.append(
                bool(
                    candidate[
                        "is_suspicious"
                    ]
                )
            )

            if candidate[
                "escalation_applied"
            ]:
                escalations.append(
                    {
                        "label": "phishing",
                        "url": url,
                        "old": old,
                        "candidate": (
                            candidate
                        ),
                    }
                )

        except Exception as error:
            errors.append(
                {
                    "label": "phishing",
                    "url": url,
                    "error": (
                        f"{type(error).__name__}: "
                        f"{error}"
                    ),
                }
            )

        if (
            index % 100
            == 0
        ):
            print(
                f"Phishing: "
                f"{index}/"
                f"{len(phishing)}"
            )

    old_metrics = metrics(
        benign_predictions=(
            old_benign
        ),

        phishing_predictions=(
            old_phishing
        ),
    )

    new_metrics = metrics(
        benign_predictions=(
            new_benign
        ),

        phishing_predictions=(
            new_phishing
        ),
    )

    report = {
        "mode": (
            "independent_holdout"
        ),

        "openphish_used_by_detector": (
            False
        ),

        "counts": {
            "benign": len(
                old_benign
            ),

            "phishing": len(
                old_phishing
            ),

            "errors": len(
                errors
            ),
        },

        "old_engine": (
            old_metrics
        ),

        "candidate_engine": (
            new_metrics
        ),

        "delta": {
            "true_positive": (
                new_metrics[
                    "true_positive"
                ]
                - old_metrics[
                    "true_positive"
                ]
            ),

            "false_positive": (
                new_metrics[
                    "false_positive"
                ]
                - old_metrics[
                    "false_positive"
                ]
            ),

            "recall": round(
                new_metrics[
                    "recall"
                ]
                - old_metrics[
                    "recall"
                ],
                4,
            ),

            "false_positive_rate": round(
                new_metrics[
                    "false_positive_rate"
                ]
                - old_metrics[
                    "false_positive_rate"
                ],
                4,
            ),

            "f1": round(
                new_metrics[
                    "f1"
                ]
                - old_metrics[
                    "f1"
                ],
                4,
            ),
        },

        "candidate_escalations": (
            escalations
        ),

        "errors": (
            errors
        ),
    }

    REPORT.write_text(
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
    report = evaluate()

    print()
    print(
        "=" * 72
    )

    print(
        "FINAL CORE INDEPENDENT HOLDOUT"
    )

    print(
        "=" * 72
    )

    print()
    print(
        "OLD ENGINE"
    )

    for key, value in report[
        "old_engine"
    ].items():
        print(
            f"  {key:<24}",
            value,
        )

    print()
    print(
        "CANDIDATE ENGINE"
    )

    for key, value in report[
        "candidate_engine"
    ].items():
        print(
            f"  {key:<24}",
            value,
        )

    print()
    print(
        "DELTA"
    )

    for key, value in report[
        "delta"
    ].items():
        print(
            f"  {key:<24}",
            value,
        )

    print()
    print(
        "Escalations:",
        len(
            report[
                "candidate_escalations"
            ]
        ),
    )

    benign_escalations = sum(
        1
        for item in report[
            "candidate_escalations"
        ]
        if item[
            "label"
        ]
        == "benign"
    )

    phishing_escalations = sum(
        1
        for item in report[
            "candidate_escalations"
        ]
        if item[
            "label"
        ]
        == "phishing"
    )

    print(
        "  benign:",
        benign_escalations,
    )

    print(
        "  phishing:",
        phishing_escalations,
    )

    print()
    print(
        "Report:",
        REPORT,
    )
