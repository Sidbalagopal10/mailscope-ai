from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from app.email_pipeline import unified_pipeline


DEFAULT_DATASET_PATH = Path(
    "data/evaluation/email_security_benchmark_v1.json"
)

DEFAULT_REPORT_PATH = Path(
    "data/evaluation/latest_benchmark_report.json"
)

DEFAULT_FALSE_POSITIVE_LIMIT = 0.10


class BenchmarkError(Exception):
    pass


def load_dataset(
    path: Path = DEFAULT_DATASET_PATH,
) -> dict[str, Any]:
    if not path.exists():
        raise BenchmarkError(
            f"Benchmark dataset was not found: {path}"
        )

    try:
        payload = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

    except json.JSONDecodeError as error:
        raise BenchmarkError(
            "Benchmark dataset contains invalid JSON."
        ) from error

    cases = payload.get(
        "cases"
    )

    if not isinstance(
        cases,
        list,
    ) or not cases:
        raise BenchmarkError(
            "Benchmark dataset contains no cases."
        )

    return payload


def authentication_headers(
    case: dict[str, Any],
) -> list[dict[str, str]]:
    sender = str(
        case.get(
            "sender",
            ""
        )
    )

    authentication = str(
        case.get(
            "authentication",
            "unknown",
        )
    ).lower()

    headers = [
        {
            "name": "From",
            "value": sender,
        }
    ]

    if authentication == "pass":
        result = (
            "mx.google.com; "
            "spf=pass smtp.mailfrom=example.com; "
            "dkim=pass header.d=example.com; "
            "dmarc=pass header.from=example.com"
        )

    elif authentication == "fail":
        result = (
            "mx.google.com; "
            "spf=fail smtp.mailfrom=attacker.example; "
            "dkim=fail header.d=attacker.example; "
            "dmarc=fail header.from=example.com"
        )

    else:
        return headers

    headers.append(
        {
            "name": "Authentication-Results",
            "value": result,
        }
    )

    return headers


def mock_deep_result(
    url: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    malicious = int(
        evidence.get(
            "virustotal_malicious",
            0,
        )
        or 0
    )

    return {
        "url": url,
        "available": True,
        "error": None,
        "final_score": float(
            evidence.get(
                "final_score",
                0,
            )
            or 0
        ),
        "risk_level": "high",
        "classification": "high_risk",
        "is_phishing": bool(
            float(
                evidence.get(
                    "final_score",
                    0,
                )
                or 0
            )
            >= 60
        ),
        "reasons": [
            "Deterministic benchmark intelligence evidence."
        ],
        "evidence_summary": {},
        "global_brand_intelligence": {
            "official_domain_match": bool(
                evidence.get(
                    "official_domain_match",
                    False,
                )
            ),
            "impersonation_detected": bool(
                evidence.get(
                    "brand_impersonation",
                    False,
                )
            ),
        },
        "threatfox_intelligence": {
            "matched": bool(
                evidence.get(
                    "threatfox_match",
                    False,
                )
            ),
        },
        "virustotal_intelligence": {
            "matched": bool(
                malicious > 0
            ),
            "maximum_malicious": malicious,
            "maximum_suspicious": 0,
        },
        "organization_intelligence": {},
        "rdap_intelligence": {},
        "dns_intelligence": {},
        "certificate_transparency": {},
        "ip_asn_intelligence": {},
        "unavailable_sources": [],
        "important_limitations": [],
    }


@contextmanager
def deterministic_deep_analysis(
    case: dict[str, Any],
) -> Iterator[None]:
    original = (
        unified_pipeline.safe_deep_url_analysis
    )

    evidence = case.get(
        "mock_deep"
    )

    def fake(
        url: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        if not isinstance(
            evidence,
            dict,
        ):
            return {
                "url": url,
                "available": True,
                "error": None,
                "final_score": 0.0,
                "risk_level": "low",
                "classification": (
                    "likely_legitimate"
                ),
                "is_phishing": False,
                "reasons": [],
                "evidence_summary": {},
                "global_brand_intelligence": {
                    "official_domain_match": False,
                    "impersonation_detected": False,
                },
                "threatfox_intelligence": {
                    "matched": False,
                },
                "virustotal_intelligence": {
                    "matched": False,
                    "maximum_malicious": 0,
                },
                "organization_intelligence": {},
                "rdap_intelligence": {},
                "dns_intelligence": {},
                "certificate_transparency": {},
                "ip_asn_intelligence": {},
                "unavailable_sources": [],
                "important_limitations": [],
            }

        return mock_deep_result(
            url,
            evidence,
        )

    unified_pipeline.safe_deep_url_analysis = fake

    try:
        yield

    finally:
        unified_pipeline.safe_deep_url_analysis = original


def run_case(
    case: dict[str, Any],
) -> dict[str, Any]:
    with deterministic_deep_analysis(
        case
    ):
        result = (
            unified_pipeline
            .analyze_email_security_pipeline(
                subject=case.get(
                    "subject",
                    "",
                ),
                body=case.get(
                    "body",
                    "",
                ),
                headers=authentication_headers(
                    case
                ),
                urls=list(
                    case.get(
                        "urls",
                        [],
                    )
                    or []
                ),
                sender_address=case.get(
                    "sender"
                ),
                known_sender=bool(
                    case.get(
                        "known_sender",
                        False,
                    )
                ),
                existing_thread=bool(
                    case.get(
                        "existing_thread",
                        False,
                    )
                ),
                sender_domain_verified=bool(
                    case.get(
                        "sender_domain_verified",
                        False,
                    )
                ),
                attachment_risk_score=float(
                    case.get(
                        "attachment_risk_score",
                        0,
                    )
                    or 0
                ),
                enable_virustotal=False,
                force_refresh=False,
            )
        )

    decision = result.get(
        "final_decision",
        {}
    )

    return {
        "id": case.get(
            "id"
        ),
        "category": case.get(
            "category"
        ),
        "true_label": int(
            case.get(
                "label",
                0,
            )
        ),
        "score": float(
            decision.get(
                "risk_score",
                0,
            )
            or 0
        ),
        "risk_level": decision.get(
            "risk_level"
        ),
        "classification": decision.get(
            "classification"
        ),
        "human_review_required": bool(
            result.get(
                "label_recommendation",
                {},
            ).get(
                "human_review_required",
                False,
            )
        ),
        "reasons": list(
            decision.get(
                "reasons",
                [],
            )
            or []
        ),
    }


def metrics_for_threshold(
    results: list[dict[str, Any]],
    threshold: float,
) -> dict[str, Any]:
    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    for result in results:
        truth = int(
            result[
                "true_label"
            ]
        )

        prediction = int(
            float(
                result[
                    "score"
                ]
            )
            >= threshold
        )

        if truth == 1 and prediction == 1:
            true_positive += 1

        elif truth == 0 and prediction == 0:
            true_negative += 1

        elif truth == 0 and prediction == 1:
            false_positive += 1

        else:
            false_negative += 1

    positive_total = (
        true_positive
        + false_negative
    )

    negative_total = (
        true_negative
        + false_positive
    )

    precision = (
        true_positive
        / (
            true_positive
            + false_positive
        )
        if (
            true_positive
            + false_positive
        )
        else 0.0
    )

    recall = (
        true_positive
        / positive_total
        if positive_total
        else 0.0
    )

    specificity = (
        true_negative
        / negative_total
        if negative_total
        else 0.0
    )

    f1 = (
        2
        * precision
        * recall
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
            true_positive
            + true_negative
        )
        / len(
            results
        )
        if results
        else 0.0
    )

    balanced_accuracy = (
        recall
        + specificity
    ) / 2

    false_positive_rate = (
        false_positive
        / negative_total
        if negative_total
        else 0.0
    )

    false_negative_rate = (
        false_negative
        / positive_total
        if positive_total
        else 0.0
    )

    return {
        "threshold": float(
            threshold
        ),
        "accuracy": round(
            accuracy,
            4,
        ),
        "balanced_accuracy": round(
            balanced_accuracy,
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
            false_positive_rate,
            4,
        ),
        "false_negative_rate": round(
            false_negative_rate,
            4,
        ),
        "true_positive": true_positive,
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,
    }


def choose_threshold(
    threshold_metrics: list[dict[str, Any]],
    *,
    maximum_false_positive_rate: float,
) -> dict[str, Any]:
    eligible = [
        item
        for item in threshold_metrics
        if float(
            item[
                "false_positive_rate"
            ]
        )
        <= maximum_false_positive_rate
    ]

    candidates = (
        eligible
        if eligible
        else threshold_metrics
    )

    return max(
        candidates,
        key=lambda item: (
            float(
                item[
                    "balanced_accuracy"
                ]
            ),
            float(
                item[
                    "f1"
                ]
            ),
            float(
                item[
                    "recall"
                ]
            ),
            -float(
                item[
                    "false_positive_rate"
                ]
            ),
        ),
    )


def category_summary(
    results: list[dict[str, Any]],
    threshold: float,
) -> list[dict[str, Any]]:
    grouped: dict[
        str,
        list[dict[str, Any]]
    ] = {}

    for result in results:
        grouped.setdefault(
            str(
                result.get(
                    "category",
                    "unknown",
                )
            ),
            [],
        ).append(
            result
        )

    summaries = []

    for category, items in sorted(
        grouped.items()
    ):
        correct = sum(
            1
            for item in items
            if int(
                float(
                    item[
                        "score"
                    ]
                )
                >= threshold
            )
            == int(
                item[
                    "true_label"
                ]
            )
        )

        summaries.append(
            {
                "category": category,
                "cases": len(
                    items
                ),
                "correct": correct,
                "accuracy": round(
                    correct
                    / len(
                        items
                    ),
                    4,
                ),
            }
        )

    return summaries


def run_benchmark(
    *,
    dataset_path: Path = DEFAULT_DATASET_PATH,
    maximum_false_positive_rate: float = (
        DEFAULT_FALSE_POSITIVE_LIMIT
    ),
) -> dict[str, Any]:
    dataset = load_dataset(
        dataset_path
    )

    results = [
        run_case(
            case
        )
        for case in dataset[
            "cases"
        ]
    ]

    threshold_metrics = [
        metrics_for_threshold(
            results,
            threshold,
        )
        for threshold in range(
            35,
            86,
            5,
        )
    ]

    recommended = choose_threshold(
        threshold_metrics,
        maximum_false_positive_rate=(
            maximum_false_positive_rate
        ),
    )

    current_threshold_metrics = (
        metrics_for_threshold(
            results,
            60.0,
        )
    )

    recommendation_threshold = float(
        recommended[
            "threshold"
        ]
    )

    report = {
        "dataset_name": dataset.get(
            "dataset_name"
        ),
        "dataset_version": dataset.get(
            "version"
        ),
        "case_count": len(
            results
        ),
        "legitimate_count": sum(
            1
            for item in results
            if item[
                "true_label"
            ]
            == 0
        ),
        "phishing_count": sum(
            1
            for item in results
            if item[
                "true_label"
            ]
            == 1
        ),
        "benchmark_type": (
            "deterministic_regression_benchmark"
        ),
        "real_world_accuracy_claim": False,
        "maximum_false_positive_rate": (
            maximum_false_positive_rate
        ),
        "current_threshold": 60.0,
        "current_threshold_metrics": (
            current_threshold_metrics
        ),
        "recommended_threshold": (
            recommendation_threshold
        ),
        "recommended_metrics": (
            recommended
        ),
        "threshold_metrics": (
            threshold_metrics
        ),
        "category_summary": (
            category_summary(
                results,
                recommendation_threshold,
            )
        ),
        "results": results,
        "automatic_threshold_change": False,
        "manual_review_required": True,
        "limitations": dataset.get(
            "limitations",
            []
        ),
    }

    DEFAULT_REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    DEFAULT_REPORT_PATH.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    return report


def load_latest_report() -> dict[str, Any] | None:
    if not DEFAULT_REPORT_PATH.exists():
        return None

    try:
        return json.loads(
            DEFAULT_REPORT_PATH.read_text(
                encoding="utf-8"
            )
        )

    except json.JSONDecodeError:
        return None
