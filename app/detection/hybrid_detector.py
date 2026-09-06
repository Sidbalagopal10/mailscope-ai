from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urlparse

from app.detection.brand_intelligence import (
    inspect_brand_impersonation,
    is_known_official_domain,
    normalize_confusables,
    normalize_hostname,
)
from app.ml.classifier import (
    URLClassifierError,
    predict_url,
)
from app.ml.url_features import (
    extract_url_features,
)


ML_WEIGHT = 0.75
HEURISTIC_WEIGHT = 0.25


SUPPLEMENTAL_BRANDS = {
    "adobe",
    "amazon",
    "americanexpress",
    "apple",
    "bankofamerica",
    "capitalone",
    "chase",
    "citi",
    "dropbox",
    "facebook",
    "github",
    "google",
    "indeed",
    "linkedin",
    "microsoft",
    "netflix",
    "paypal",
    "stripe",
    "wellsfargo",
    "workday",
}


def clamp(
    value: float,
    minimum: float = 0.0,
    maximum: float = 100.0,
) -> float:
    return max(
        minimum,
        min(
            float(value),
            maximum,
        ),
    )


def supplemental_brand_check(
    url: str,
    existing_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Add a fallback typo-brand check when the primary brand engine
    misses a close spelling such as linkedln versus linkedin.

    Official domains are never treated as impersonation here.
    """
    result = dict(
        existing_result
    )

    result["findings"] = list(
        existing_result.get(
            "findings",
            [],
        )
    )

    if result.get(
        "impersonation_detected",
        False,
    ):
        return result

    parsed = urlparse(
        str(url or "").strip()
    )

    hostname = normalize_hostname(
        parsed.hostname or ""
    )

    if (
        not hostname
        or is_known_official_domain(
            hostname
        )
    ):
        return result

    hostname_tokens = [
        token
        for token in re.split(
            r"[^a-zA-Z0-9]+",
            hostname,
        )
        if token
    ]

    strongest_finding = None

    for token in hostname_tokens:
        normalized_token = normalize_confusables(
            token
        )

        if len(
            normalized_token
        ) < 4:
            continue

        for brand in SUPPLEMENTAL_BRANDS:
            normalized_brand = normalize_confusables(
                brand
            )

            similarity = SequenceMatcher(
                None,
                normalized_token,
                normalized_brand,
            ).ratio()

            if (
                normalized_token
                == normalized_brand
            ):
                severity = 24
                finding_type = (
                    "brand_on_unofficial_domain"
                )

            elif similarity >= 0.84:
                severity = 36
                finding_type = (
                    "brand_typo"
                )

            else:
                continue

            finding = {
                "brand": brand,
                "type": finding_type,
                "similarity": round(
                    similarity,
                    4,
                ),
                "severity": severity,
                "reason": (
                    f"The hostname contains '{token}', "
                    f"which closely resembles the brand "
                    f"'{brand}' on an unofficial domain."
                ),
            }

            if (
                strongest_finding is None
                or finding["severity"]
                > strongest_finding[
                    "severity"
                ]
                or (
                    finding["severity"]
                    == strongest_finding[
                        "severity"
                    ]
                    and finding[
                        "similarity"
                    ]
                    > strongest_finding[
                        "similarity"
                    ]
                )
            ):
                strongest_finding = finding

    if strongest_finding is None:
        return result

    result[
        "impersonation_detected"
    ] = True

    result[
        "strongest_finding"
    ] = strongest_finding

    result["findings"].insert(
        0,
        strongest_finding,
    )

    result["findings"] = result[
        "findings"
    ][:5]

    return result


def calculate_heuristic_score(
    url: str,
    *,
    features: dict[str, Any] | None = None,
    brand: dict[str, Any] | None = None,
) -> tuple[
    float,
    list[str],
]:
    if features is None:
        features = extract_url_features(
            url
        )

    if brand is None:
        brand = supplemental_brand_check(
            url,
            inspect_brand_impersonation(
                url
            ),
        )

    score = 0.0
    reasons: list[str] = []

    tracking_domain = bool(
        features.get(
            "is_tracking_domain",
            0,
        )
    )

    if features["hostname_is_ip"]:
        score += 30

        reasons.append(
            "The URL uses an IP address "
            "instead of a normal domain."
        )

    if features["uses_http"]:
        score += 8

        reasons.append(
            "The URL does not use HTTPS."
        )

    if features[
        "contains_punycode"
    ]:
        score += 18

        reasons.append(
            "The hostname contains punycode."
        )

    if features[
        "contains_suspicious_port"
    ]:
        score += 12

        reasons.append(
            "The URL uses an unusual port."
        )

    if features[
        "count_at_symbols"
    ]:
        score += 22

        reasons.append(
            "The URL contains an @ symbol "
            "that may disguise its destination."
        )

    high_signal_count = int(
        features.get(
            "count_high_signal_keywords",
            0,
        )
        or 0
    )

    if high_signal_count >= 3:
        score += 16

        reasons.append(
            "The URL contains several "
            "credential-related terms."
        )

    elif high_signal_count == 2:
        score += 11

        reasons.append(
            "The URL contains multiple "
            "credential-related terms."
        )

    elif high_signal_count == 1:
        score += 5

        reasons.append(
            "The URL contains a "
            "credential-related term."
        )

    business_count = int(
        features.get(
            "count_business_keywords",
            0,
        )
        or 0
    )

    if (
        business_count >= 2
        and high_signal_count >= 1
    ):
        score += 5

        reasons.append(
            "Business terminology appears "
            "together with credential language."
        )

    if features[
        "uses_url_shortener"
    ]:
        score += 7

        reasons.append(
            "The URL uses a shortening service."
        )

    if brand.get(
        "impersonation_detected",
        False,
    ):
        strongest = (
            brand.get(
                "strongest_finding"
            )
            or {}
        )

        score += float(
            strongest.get(
                "severity",
                0,
            )
            or 0
        )

        reason = strongest.get(
            "reason"
        )

        if reason:
            reasons.append(
                reason
            )

    if (
        int(
            features.get(
                "count_subdomains",
                0,
            )
            or 0
        )
        >= 4
    ):
        score += 9

        reasons.append(
            "The hostname has an unusually "
            "deep subdomain structure."
        )

    url_length = int(
        features.get(
            "url_length",
            0,
        )
        or 0
    )

    if not tracking_domain:
        if url_length >= 250:
            score += 6

            reasons.append(
                "The URL is exceptionally long."
            )

        elif url_length >= 150:
            score += 3

            reasons.append(
                "The URL is relatively long."
            )

    if (
        features.get(
            "contains_encoded_characters",
            0,
        )
        and not tracking_domain
    ):
        score += 4

        reasons.append(
            "The URL contains encoded characters."
        )

    if (
        float(
            features.get(
                "digit_ratio",
                0,
            )
            or 0
        )
        >= 0.35
        and not tracking_domain
    ):
        score += 5

        reasons.append(
            "The URL contains an unusually "
            "high proportion of digits."
        )

    if tracking_domain:
        reasons.append(
            "The URL appears to be a marketing "
            "or tracking link; complexity alone "
            "was not treated as phishing."
        )

        if (
            not features[
                "hostname_is_ip"
            ]
            and not brand.get(
                "impersonation_detected",
                False,
            )
            and high_signal_count == 0
            and not features[
                "contains_suspicious_port"
            ]
        ):
            score = min(
                score,
                12,
            )

    if not reasons:
        reasons.append(
            "No strong lexical phishing "
            "indicators were detected."
        )

    return (
        round(
            clamp(
                score
            ),
            2,
        ),
        reasons,
    )


def evaluate_corroborating_evidence(
    *,
    features: dict[str, Any],
    brand_result: dict[str, Any],
    heuristic_score: float,
) -> dict[str, Any]:
    """
    Measure evidence independent of the ML prediction.

    ML alone cannot produce a HIGH or CRITICAL result.
    """
    strong_signals: list[str] = []
    weak_signals: list[str] = []

    brand_impersonation = bool(
        brand_result.get(
            "impersonation_detected",
            False,
        )
    )

    if brand_impersonation:
        strong_signals.append(
            "Brand impersonation or typo-domain evidence"
        )

    if bool(
        features.get(
            "hostname_is_ip",
            0,
        )
    ):
        strong_signals.append(
            "IP-address hostname"
        )

    if bool(
        features.get(
            "contains_punycode",
            0,
        )
    ):
        strong_signals.append(
            "Punycode or internationalized hostname"
        )

    if bool(
        features.get(
            "contains_suspicious_port",
            0,
        )
    ):
        strong_signals.append(
            "Unusual network port"
        )

    if bool(
        features.get(
            "count_at_symbols",
            0,
        )
    ):
        strong_signals.append(
            "Destination-obscuring @ symbol"
        )

    high_signal_count = int(
        features.get(
            "count_high_signal_keywords",
            0,
        )
        or 0
    )

    if high_signal_count >= 2:
        strong_signals.append(
            "Multiple credential or verification terms"
        )

    elif (
        high_signal_count == 1
        and brand_impersonation
    ):
        strong_signals.append(
            "Credential lure combined with brand impersonation"
        )

    elif high_signal_count == 1:
        weak_signals.append(
            "One credential-related URL term"
        )

    if bool(
        features.get(
            "uses_http",
            0,
        )
    ):
        weak_signals.append(
            "URL does not use HTTPS"
        )

    if bool(
        features.get(
            "uses_url_shortener",
            0,
        )
    ):
        weak_signals.append(
            "URL shortening service"
        )

    if (
        int(
            features.get(
                "count_subdomains",
                0,
            )
            or 0
        )
        >= 4
    ):
        weak_signals.append(
            "Unusually deep subdomain structure"
        )

    if (
        bool(
            features.get(
                "contains_encoded_characters",
                0,
            )
        )
        and not bool(
            features.get(
                "is_tracking_domain",
                0,
            )
        )
    ):
        weak_signals.append(
            "Encoded URL characters"
        )

    if (
        float(
            features.get(
                "digit_ratio",
                0,
            )
            or 0
        )
        >= 0.35
        and not bool(
            features.get(
                "is_tracking_domain",
                0,
            )
        )
    ):
        weak_signals.append(
            "Unusually high digit ratio"
        )

    strong_count = len(
        strong_signals
    )

    weak_count = len(
        weak_signals
    )

    if strong_count >= 2:
        evidence_level = (
            "multiple_strong_signals"
        )

        maximum_score = 100.0

    elif strong_count == 1:
        evidence_level = (
            "one_strong_signal"
        )

        maximum_score = 69.0

    elif weak_count >= 2:
        evidence_level = (
            "multiple_weak_signals"
        )

        maximum_score = 49.0

    elif weak_count == 1:
        evidence_level = (
            "one_weak_signal"
        )

        maximum_score = 39.0

    else:
        evidence_level = (
            "no_independent_signal"
        )

        maximum_score = 34.0

    return {
        "strong_signal_count": (
            strong_count
        ),
        "weak_signal_count": (
            weak_count
        ),
        "strong_signals": (
            strong_signals
        ),
        "weak_signals": (
            weak_signals
        ),
        "evidence_level": (
            evidence_level
        ),
        "maximum_score_without_more_evidence": (
            maximum_score
        ),
        "heuristic_score": (
            heuristic_score
        ),
    }


def determine_risk_level(
    score: float,
) -> str:
    if score >= 75:
        return "critical"

    if score >= 55:
        return "high"

    if score >= 35:
        return "medium"

    if score >= 20:
        return "guarded"

    return "low"


def calculate_confidence(
    *,
    official_domain: bool,
    ml_available: bool,
    ml_probability: float,
    corroboration: dict[str, Any],
) -> float:
    strong_count = int(
        corroboration[
            "strong_signal_count"
        ]
    )

    weak_count = int(
        corroboration[
            "weak_signal_count"
        ]
    )

    if official_domain:
        confidence = 88.0

    elif strong_count >= 2:
        confidence = 92.0

    elif strong_count == 1:
        confidence = 78.0

    elif weak_count >= 2:
        confidence = 66.0

    elif weak_count == 1:
        confidence = 58.0

    else:
        confidence = 48.0

    if ml_available:
        distance_from_uncertainty = abs(
            ml_probability - 0.5
        ) * 2

        confidence += (
            distance_from_uncertainty
            * 5
        )

    return round(
        clamp(
            confidence,
            0,
            99,
        ),
        2,
    )


def analyze_url_hybrid(
    url: str,
) -> dict[str, Any]:
    url_features = extract_url_features(
        url
    )

    original_brand_result = (
        inspect_brand_impersonation(
            url
        )
    )

    brand_result = (
        supplemental_brand_check(
            url,
            original_brand_result,
        )
    )

    heuristic_score, heuristic_reasons = (
        calculate_heuristic_score(
            url,
            features=url_features,
            brand=brand_result,
        )
    )

    parsed_url = urlparse(
        str(url or "").strip()
    )

    hostname = normalize_hostname(
        parsed_url.hostname or ""
    )

    official_domain = bool(
        is_known_official_domain(
            hostname
        )
    )

    ml_available = True
    ml_error = None

    try:
        ml_result = predict_url(
            url
        )

        ml_probability = float(
            ml_result[
                "phishing_probability"
            ]
        )

        raw_ml_probability = float(
            ml_result.get(
                "probability_before_guardrail",
                ml_probability,
            )
            or ml_probability
        )

        ml_score = (
            ml_probability * 100
        )

    except (
        URLClassifierError,
        FileNotFoundError,
        ValueError,
        RuntimeError,
    ) as error:
        ml_available = False
        ml_error = str(
            error
        )
        ml_probability = 0.0
        raw_ml_probability = 0.0
        ml_score = 0.0

        ml_result = {
            "classification": (
                "unavailable"
            ),
            "model_type": (
                "unavailable"
            ),
            "model_version": (
                "unavailable"
            ),
            "decision_threshold": None,
            "official_domain_guardrail": (
                False
            ),
        }

    if ml_available:
        score_before_evidence = (
            ml_score * ML_WEIGHT
            + heuristic_score
            * HEURISTIC_WEIGHT
        )

    else:
        score_before_evidence = (
            heuristic_score
        )

    strongest_brand = (
        brand_result.get(
            "strongest_finding"
        )
        or {}
    )

    brand_severity = float(
        strongest_brand.get(
            "severity",
            0,
        )
        or 0
    )

    if brand_severity >= 34:
        score_before_evidence = max(
            score_before_evidence,
            72,
        )

    elif brand_severity >= 22:
        score_before_evidence = max(
            score_before_evidence,
            52,
        )

    if brand_result.get(
        "tracking_domain",
        False,
    ):
        tracking_has_strong_evidence = any(
            [
                brand_result.get(
                    "impersonation_detected",
                    False,
                ),
                heuristic_score >= 30,
                bool(
                    url_features.get(
                        "hostname_is_ip",
                        0,
                    )
                ),
                int(
                    url_features.get(
                        "count_high_signal_keywords",
                        0,
                    )
                    or 0
                )
                >= 2,
            ]
        )

        if not tracking_has_strong_evidence:
            score_before_evidence = min(
                score_before_evidence,
                34,
            )

    corroboration = (
        evaluate_corroborating_evidence(
            features=url_features,
            brand_result=brand_result,
            heuristic_score=heuristic_score,
        )
    )

    corroboration_cap = float(
        corroboration[
            "maximum_score_without_more_evidence"
        ]
    )

    final_score = min(
        score_before_evidence,
        corroboration_cap,
    )

    official_guardrail_applied = bool(
        ml_result.get(
            "official_domain_guardrail",
            False,
        )
    )

    if (
        official_domain
        and official_guardrail_applied
        and corroboration[
            "strong_signal_count"
        ]
        == 0
        and heuristic_score < 20
    ):
        final_score = min(
            final_score,
            18,
        )

    final_score = round(
        clamp(
            final_score
        ),
        2,
    )

    corroboration_cap_applied = bool(
        final_score
        < round(
            clamp(
                score_before_evidence
            ),
            2,
        )
    )

    risk_level = determine_risk_level(
        final_score
    )

    confidence_percentage = (
        calculate_confidence(
            official_domain=official_domain,
            ml_available=ml_available,
            ml_probability=ml_probability,
            corroboration=corroboration,
        )
    )

    reasons = list(
        heuristic_reasons
    )

    if ml_available:
        reasons.append(
            "Calibrated model phishing "
            f"probability: "
            f"{ml_probability * 100:.1f}%."
        )

        if (
            raw_ml_probability
            != ml_probability
        ):
            reasons.append(
                "The raw model probability was "
                f"{raw_ml_probability * 100:.1f}% "
                "before an official-domain safeguard."
            )

    else:
        reasons.append(
            "The ML model was unavailable; "
            "the result uses explainable "
            "lexical analysis only."
        )

    if corroboration_cap_applied:
        reasons.append(
            "The ML-driven score was limited because "
            "there was insufficient independent "
            "phishing evidence."
        )

    if (
        corroboration[
            "strong_signal_count"
        ]
        >= 2
    ):
        reasons.append(
            "Multiple independent phishing indicators "
            "corroborated the model prediction."
        )

    if official_domain:
        official_explanation = (
            "The hostname is a conditionally recognized "
            "official domain. This provided positive "
            "evidence only because no contradictory "
            "high-risk indicators were present."
        )

    else:
        official_explanation = (
            "The domain is not in the curated official "
            "set. No penalty was applied because unknown "
            "domains are neutral."
        )

    return {
        "url": url,
        "final_score": (
            final_score
        ),
        "confidence_percentage": (
            confidence_percentage
        ),
        "confidence_level": (
            "high"
            if confidence_percentage >= 80
            else (
                "medium"
                if confidence_percentage >= 60
                else "low"
            )
        ),
        "risk_level": (
            risk_level
        ),
        "domain_reputation": (
            "conditionally_trusted"
            if official_domain
            else "unknown"
        ),
        "is_suspicious": (
            final_score >= 35
        ),
        "is_phishing": (
            final_score >= 70
        ),
        "classification": (
            "likely_phishing"
            if final_score >= 70
            else (
                "high_risk"
                if final_score >= 50
                else (
                    "suspicious"
                    if final_score >= 35
                    else (
                        "needs_review"
                        if final_score >= 20
                        else "likely_legitimate"
                    )
                )
            )
        ),
        "recommendation": (
            "Do not open this URL until "
            "the destination is independently "
            "verified."
            if final_score >= 70
            else (
                "Treat this URL as high risk and "
                "verify it through an independent source."
                if final_score >= 50
                else (
                    "Verify the sender and destination "
                    "before opening this URL."
                    if final_score >= 35
                    else (
                        "There is insufficient evidence "
                        "to call this URL phishing or "
                        "confirmed legitimate. Verify the "
                        "organization independently."
                        if final_score >= 20
                        else (
                            "No strong phishing evidence "
                            "was detected, but normal "
                            "caution still applies."
                        )
                    )
                )
            )
        ),
        "reasons": reasons,
        "brand_intelligence": (
            brand_result
        ),
        "official_domain_evidence": {
            "recognized": (
                official_domain
            ),
            "ml_guardrail_applied": (
                official_guardrail_applied
            ),
            "unknown_domain_penalty": 0,
            "explanation": (
                official_explanation
            ),
        },
        "corroborating_evidence": {
            **corroboration,
            "score_before_corroboration": round(
                clamp(
                    score_before_evidence
                ),
                2,
            ),
            "final_score_cap_applied": (
                corroboration_cap_applied
            ),
            "explanation": (
                "The raw ML-driven score was capped "
                "because independent phishing evidence "
                "was insufficient."
                if corroboration_cap_applied
                else (
                    "The final score was supported by "
                    "the available independent evidence."
                )
            ),
        },
        "components": {
            "heuristic": {
                "score": (
                    heuristic_score
                ),
                "weight": (
                    HEURISTIC_WEIGHT
                    if ml_available
                    else 1.0
                ),
                "reasons": (
                    heuristic_reasons
                ),
            },
            "machine_learning": {
                "available": (
                    ml_available
                ),
                "score": round(
                    ml_score,
                    2,
                ),
                "probability": round(
                    ml_probability,
                    6,
                ),
                "raw_probability": round(
                    raw_ml_probability,
                    6,
                ),
                "weight": (
                    ML_WEIGHT
                    if ml_available
                    else 0.0
                ),
                "classification": (
                    ml_result.get(
                        "classification"
                    )
                ),
                "model_type": (
                    ml_result.get(
                        "model_type"
                    )
                ),
                "model_version": (
                    ml_result.get(
                        "model_version"
                    )
                ),
                "decision_threshold": (
                    ml_result.get(
                        "decision_threshold"
                    )
                ),
                "official_domain_guardrail": (
                    official_guardrail_applied
                ),
                "error": (
                    ml_error
                ),
            },
        },
    }
