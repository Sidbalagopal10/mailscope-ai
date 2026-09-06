from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from app.domain_intelligence.threatfox_relevance import (
    normalize_hostname,
    sanitize_threatfox_payload,
)
from app.domain_intelligence.unified_profile import (
    analyze_unified_domain_profile as analyze_legacy_unified_domain_profile,
)


OFFICIAL_DOMAIN_OVERRIDES: dict[
    str,
    dict[str, Any],
] = {
    "google.com": {
        "brand": "Google",
        "confidence": 1.0,
    },
    "microsoft.com": {
        "brand": "Microsoft",
        "confidence": 1.0,
    },
    "apple.com": {
        "brand": "Apple",
        "confidence": 1.0,
    },
    "nvidia.com": {
        "brand": "NVIDIA",
        "confidence": 1.0,
    },
    "github.com": {
        "brand": "GitHub",
        "confidence": 1.0,
    },
    "gwu.edu": {
        "brand": (
            "The George Washington University"
        ),
        "confidence": 1.0,
    },
}


def clamp(
    value: float,
    minimum: float = 0.0,
    maximum: float = 100.0,
) -> float:
    return max(
        minimum,
        min(
            float(
                value
            ),
            maximum,
        ),
    )


def risk_level_for_score(
    score: float,
) -> str:
    if score >= 80:
        return "critical"

    if score >= 60:
        return "high"

    if score >= 35:
        return "moderate"

    return "low"


def classification_for_score(
    score: float,
) -> str:
    if score >= 80:
        return "likely_phishing"

    if score >= 60:
        return "high_risk"

    if score >= 35:
        return "needs_review"

    return "likely_legitimate"


def input_hostname(
    value: str,
) -> str:
    cleaned = str(
        value or ""
    ).strip()

    if not cleaned:
        return ""

    if cleaned.lower().startswith(
        (
            "http://",
            "https://",
        )
    ):
        try:
            return normalize_hostname(
                urlsplit(
                    cleaned
                ).hostname
            )
        except ValueError:
            return ""

    return normalize_hostname(
        cleaned.split(
            "/",
            1,
        )[0]
    )


def ensure_official_identity(
    result: dict[str, Any],
    hostname: str,
) -> tuple[
    dict[str, Any],
    bool,
]:
    brand = dict(
        result.get(
            "global_brand_intelligence",
            {},
        )
        or {}
    )

    already_official = bool(
        brand.get(
            "official_domain_match",
            False,
        )
    )

    override = OFFICIAL_DOMAIN_OVERRIDES.get(
        hostname
    )

    if override is None:
        return brand, already_official

    brand[
        "official_domain_match"
    ] = True

    brand[
        "impersonation_detected"
    ] = False

    brand[
        "matched_brand"
    ] = override[
        "brand"
    ]

    brand[
        "official_domain"
    ] = hostname

    brand[
        "identity_confidence"
    ] = override[
        "confidence"
    ]

    brand[
        "official_identity_source"
    ] = (
        "verified_local_override"
    )

    return brand, True


def safe_score_after_filtered_threatfox(
    result: dict[str, Any],
) -> float:
    try:
        hybrid_score = float(
            result.get(
                "base_hybrid_score",
                (
                    result.get(
                        "hybrid_detection",
                        {},
                    )
                    or {}
                ).get(
                    "final_score",
                    0.0,
                ),
            )
            or 0.0
        )
    except (
        TypeError,
        ValueError,
    ):
        hybrid_score = 0.0

    try:
        total_adjustment = float(
            result.get(
                "total_intelligence_adjustment",
                0.0,
            )
            or 0.0
        )
    except (
        TypeError,
        ValueError,
    ):
        total_adjustment = 0.0

    threatfox = (
        result.get(
            "threatfox_intelligence",
            {},
        )
        or {}
    )

    try:
        threatfox_adjustment = float(
            threatfox.get(
                "applied_score_adjustment",
                0.0,
            )
            or threatfox.get(
                "risk_adjustment",
                0.0,
            )
            or 0.0
        )
    except (
        TypeError,
        ValueError,
    ):
        threatfox_adjustment = 0.0

    if threatfox_adjustment == 0 and total_adjustment >= 30:
        threatfox_adjustment = 30.0

    corrected_adjustment = (
        total_adjustment
        - max(
            0.0,
            threatfox_adjustment,
        )
    )

    return clamp(
        hybrid_score
        + corrected_adjustment
    )


def analyze_safe_unified_domain_profile(
    value: str,
    *,
    force_refresh: bool = False,
    include_ct_subdomains: bool = False,
) -> dict[str, Any]:
    result = dict(
        analyze_legacy_unified_domain_profile(
            value,
            force_refresh=force_refresh,
            include_ct_subdomains=(
                include_ct_subdomains
            ),
        )
    )

    hostname = input_hostname(
        value
    )

    original_threatfox = dict(
        result.get(
            "threatfox_intelligence",
            {},
        )
        or {}
    )

    sanitized_threatfox = (
        sanitize_threatfox_payload(
            original_threatfox,
            hostname,
        )
    )

    result[
        "threatfox_intelligence"
    ] = sanitized_threatfox

    brand, official = (
        ensure_official_identity(
            result,
            hostname,
        )
    )

    result[
        "global_brand_intelligence"
    ] = brand

    false_positive_filtered = bool(
        sanitized_threatfox.get(
            "false_positive_filtered",
            False,
        )
    )

    if false_positive_filtered:
        corrected_score = (
            safe_score_after_filtered_threatfox(
                result
            )
        )

        result[
            "legacy_final_score_before_safety_guard"
        ] = result.get(
            "final_score"
        )

        result[
            "final_score"
        ] = round(
            corrected_score,
            2,
        )

        result[
            "risk_score"
        ] = round(
            corrected_score,
            2,
        )

        result[
            "risk_level"
        ] = risk_level_for_score(
            corrected_score
        )

        result[
            "classification"
        ] = classification_for_score(
            corrected_score
        )

        result[
            "is_phishing"
        ] = bool(
            corrected_score >= 60
        )

        result[
            "total_intelligence_adjustment"
        ] = round(
            corrected_score
            - float(
                result.get(
                    "base_hybrid_score",
                    (
                        result.get(
                            "hybrid_detection",
                            {},
                        )
                        or {}
                    ).get(
                        "final_score",
                        0.0,
                    ),
                )
                or 0.0
            ),
            2,
        )

    reasons = [
        str(
            reason
        )
        for reason in (
            result.get(
                "reasons",
                [],
            )
            or []
        )
        if not (
            false_positive_filtered
            and "threatfox"
            in str(
                reason
            ).lower()
            and any(
                term in str(
                    reason
                ).lower()
                for term in (
                    "match",
                    "malicious",
                    "ioc",
                )
            )
        )
    ]

    if false_positive_filtered:
        reasons.append(
            "ThreatFox Safety Guard: an unrelated or merely "
            "similar IOC was rejected because its hostname did "
            "not exactly match the requested domain or a true "
            "subdomain."
        )

    if official:
        reasons.append(
            "Identity Evidence: the hostname is an exact verified "
            "official domain. Identity evidence does not guarantee "
            "that every page or account on the domain is safe."
        )

    result[
        "reasons"
    ] = list(
        dict.fromkeys(
            reasons
        )
    )

    evidence_summary = dict(
        result.get(
            "evidence_summary",
            {},
        )
        or {}
    )

    evidence_summary.update(
        {
            "requested_hostname": hostname,
            "official_domain_match": (
                official
            ),
            "threatfox_relevance_validated": True,
            "threatfox_relevant_match": bool(
                sanitized_threatfox.get(
                    "matched",
                    False,
                )
            ),
            "threatfox_false_positive_filtered": (
                false_positive_filtered
            ),
        }
    )

    result[
        "evidence_summary"
    ] = evidence_summary

    result[
        "domain_safety_guard"
    ] = {
        "enabled": True,
        "requested_hostname": hostname,
        "official_domain_match": official,
        "threatfox_relevance_validated": True,
        "threatfox_false_positive_filtered": (
            false_positive_filtered
        ),
        "relevant_threatfox_iocs": (
            sanitized_threatfox.get(
                "relevant_iocs",
                [],
            )
        ),
    }

    return result


analyze_unified_domain_profile = (
    analyze_safe_unified_domain_profile
)
