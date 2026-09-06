from __future__ import annotations

from typing import Any


MALICIOUS_CATEGORY_TERMS = {
    "malware",
    "phishing",
    "malicious",
    "command and control",
    "botnet",
    "spam",
    "scam",
    "fraud",
}


def category_is_suspicious(
    category: str,
) -> bool:
    normalized = str(
        category or ""
    ).strip().lower()

    return any(
        term in normalized
        for term in MALICIOUS_CATEGORY_TERMS
    )


def virustotal_risk_evidence(
    observation: dict[str, Any] | None,
) -> dict[str, Any]:
    if not observation:
        return {
            "available": False,
            "matched": False,
            "risk_adjustment": 0.0,
            "confidence_adjustment": 0.0,
            "strong_signals": [],
            "weak_signals": [],
            "positive_signals": [],
            "reasons": [
                "No VirusTotal observation is available."
            ],
        }

    if observation.get(
        "lookup_status"
    ) != "success":
        return {
            "available": False,
            "matched": False,
            "risk_adjustment": 0.0,
            "confidence_adjustment": 0.0,
            "strong_signals": [],
            "weak_signals": [],
            "positive_signals": [],
            "reasons": [
                (
                    "VirusTotal was unavailable. An API failure "
                    "does not make the indicator suspicious."
                )
            ],
        }

    if not observation.get(
        "object_found"
    ):
        return {
            "available": True,
            "matched": False,
            "risk_adjustment": 0.0,
            "confidence_adjustment": 0.0,
            "strong_signals": [],
            "weak_signals": [],
            "positive_signals": [],
            "reasons": [
                (
                    "VirusTotal has no existing report for this "
                    "indicator. Absence of a report does not prove safety."
                )
            ],
        }

    malicious = int(
        observation.get(
            "malicious",
            0,
        )
        or 0
    )

    suspicious = int(
        observation.get(
            "suspicious",
            0,
        )
        or 0
    )

    harmless = int(
        observation.get(
            "harmless",
            0,
        )
        or 0
    )

    total_engines = int(
        observation.get(
            "total_engines",
            0,
        )
        or 0
    )

    categories = list(
        observation.get(
            "categories",
            [],
        )
        or []
    )

    suspicious_categories = [
        category
        for category in categories
        if category_is_suspicious(
            category
        )
    ]

    strong_signals: list[str] = []
    weak_signals: list[str] = []
    positive_signals: list[str] = []
    reasons: list[str] = []

    adjustment = 0.0
    confidence_adjustment = 0.0

    if malicious >= 10:
        adjustment = 65.0
        confidence_adjustment = 20.0

        strong_signals.append(
            "At least 10 VirusTotal engines classified "
            "the indicator as malicious."
        )

    elif malicious >= 5:
        adjustment = 55.0
        confidence_adjustment = 18.0

        strong_signals.append(
            "Multiple VirusTotal engines classified "
            "the indicator as malicious."
        )

    elif malicious >= 2:
        adjustment = 42.0
        confidence_adjustment = 14.0

        strong_signals.append(
            "More than one VirusTotal engine classified "
            "the indicator as malicious."
        )

    elif malicious == 1:
        adjustment = 16.0
        confidence_adjustment = 6.0

        weak_signals.append(
            "One VirusTotal engine classified the indicator "
            "as malicious; isolated detections can be false positives."
        )

    if suspicious >= 5:
        adjustment = max(
            adjustment,
            30.0,
        )

        weak_signals.append(
            "Several VirusTotal engines marked the indicator suspicious."
        )

    elif suspicious >= 1:
        adjustment = max(
            adjustment,
            8.0,
        )

        weak_signals.append(
            "At least one VirusTotal engine marked the indicator suspicious."
        )

    if suspicious_categories:
        adjustment = max(
            adjustment,
            18.0,
        )

        weak_signals.append(
            "VirusTotal category providers associated the indicator "
            "with phishing, malware, fraud, spam, or related activity."
        )

    if (
        malicious == 0
        and suspicious == 0
        and harmless >= 10
    ):
        positive_signals.append(
            "VirusTotal engines reported no malicious or suspicious detections."
        )

        confidence_adjustment += 3.0

    matched = bool(
        malicious > 0
        or suspicious > 0
        or suspicious_categories
    )

    reasons.append(
        (
            f"VirusTotal detections: {malicious} malicious, "
            f"{suspicious} suspicious, {harmless} harmless, "
            f"{total_engines} total engine results."
        )
    )

    if suspicious_categories:
        reasons.append(
            "Suspicious categories: "
            + ", ".join(
                suspicious_categories[:10]
            )
        )

    return {
        "available": True,
        "matched": matched,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "total_engines": total_engines,
        "risk_adjustment": round(
            min(
                adjustment,
                65.0,
            ),
            2,
        ),
        "confidence_adjustment": round(
            min(
                confidence_adjustment,
                20.0,
            ),
            2,
        ),
        "strong_signals": strong_signals,
        "weak_signals": weak_signals,
        "positive_signals": positive_signals,
        "reasons": reasons,
        "important_limitations": [
            (
                "VirusTotal aggregates third-party detections; "
                "an isolated engine result may be a false positive."
            ),
            (
                "No VirusTotal detection does not prove that an "
                "indicator is safe."
            ),
            (
                "VirusTotal results may be stale or may not yet "
                "include newly created phishing infrastructure."
            ),
            (
                "Public API results are quota limited and are "
                "used selectively with local caching."
            ),
        ],
    }


def combine_virustotal_evidence(
    lookup: dict[str, Any] | None,
) -> dict[str, Any]:
    lookup = lookup or {}

    url_observation = lookup.get(
        "url_result"
    )

    domain_observation = lookup.get(
        "domain_result"
    )

    url_evidence = virustotal_risk_evidence(
        url_observation
    )

    domain_evidence = virustotal_risk_evidence(
        domain_observation
    )

    matched = bool(
        url_evidence.get(
            "matched"
        )
        or domain_evidence.get(
            "matched"
        )
    )

    risk_adjustment = max(
        float(
            url_evidence.get(
                "risk_adjustment",
                0,
            )
            or 0
        ),
        float(
            domain_evidence.get(
                "risk_adjustment",
                0,
            )
            or 0
        ),
    )

    confidence_adjustment = max(
        float(
            url_evidence.get(
                "confidence_adjustment",
                0,
            )
            or 0
        ),
        float(
            domain_evidence.get(
                "confidence_adjustment",
                0,
            )
            or 0
        ),
    )

    return {
        "matched": matched,
        "risk_adjustment": (
            risk_adjustment
        ),
        "confidence_adjustment": (
            confidence_adjustment
        ),
        "url_evidence": url_evidence,
        "domain_evidence": domain_evidence,
        "url_observation": (
            url_observation
        ),
        "domain_observation": (
            domain_observation
        ),
    }
