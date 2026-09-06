from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from app.detection.hybrid_detector import (
    analyze_url_hybrid,
    clamp,
    determine_risk_level,
)
from app.organization_intelligence.scoring import (
    identity_score_adjustment,
)
from app.organization_intelligence.store import (
    normalize_domain,
)


def classify_score(
    score: float,
) -> str:
    if score >= 70:
        return "likely_phishing"

    if score >= 50:
        return "high_risk"

    if score >= 35:
        return "suspicious"

    if score >= 20:
        return "needs_review"

    return "likely_legitimate"


def recommendation_for_score(
    score: float,
) -> str:
    if score >= 70:
        return (
            "Do not open this URL until the destination "
            "is independently verified."
        )

    if score >= 50:
        return (
            "Treat this URL as high risk and verify it "
            "through an independent source."
        )

    if score >= 35:
        return (
            "Verify the sender and destination before "
            "opening this URL."
        )

    if score >= 20:
        return (
            "There is insufficient evidence to call this "
            "URL phishing or confirmed legitimate. Verify "
            "the organization independently."
        )

    return (
        "No strong phishing evidence was detected, but "
        "normal caution still applies."
    )


def analyze_url_with_organization_intelligence(
    url: str,
) -> dict[str, Any]:
    """
    Combine the existing hybrid URL detector with organization
    identity evidence.

    Organization identity is supporting evidence only. It cannot
    suppress strong phishing indicators such as impersonation,
    credential lures, IP-hosted URLs, punycode, or compromised
    reputation.
    """
    result = analyze_url_hybrid(
        url
    )

    parsed = urlparse(
        str(url or "").strip()
    )

    hostname = (
        parsed.hostname
        or ""
    )

    try:
        normalized_hostname = normalize_domain(
            hostname
        )

    except Exception:
        normalized_hostname = (
            hostname.lower().rstrip(".")
        )

    identity = identity_score_adjustment(
        normalized_hostname
    )

    original_score = float(
        result.get(
            "final_score",
            0.0,
        )
        or 0.0
    )

    corroboration = result.get(
        "corroborating_evidence",
        {},
    )

    strong_signal_count = int(
        corroboration.get(
            "strong_signal_count",
            0,
        )
        or 0
    )

    brand_impersonation = bool(
        result.get(
            "brand_intelligence",
            {},
        ).get(
            "impersonation_detected",
            False,
        )
    )

    identity_state = identity.get(
        "identity_state",
        "UNKNOWN",
    )

    security_state = identity.get(
        "security_state",
        "NEUTRAL",
    )

    requested_adjustment = float(
        identity.get(
            "score_adjustment",
            0.0,
        )
        or 0.0
    )

    applied_adjustment = 0.0
    adjustment_blocked = False
    adjustment_reason = (
        "No organization identity adjustment was required."
    )

    malicious_security_states = {
        "KNOWN_MALICIOUS",
        "COMPROMISED_LEGITIMATE",
        "SUSPICIOUS",
    }

    positive_identity_states = {
        "VERIFIED_ESTABLISHED",
        "VERIFIED_NEW",
        "OBSERVED_LEGITIMATE",
        "PROVISIONAL",
    }

    if security_state in malicious_security_states:
        applied_adjustment = max(
            requested_adjustment,
            0.0,
        )

        adjustment_reason = (
            "Current security reputation increased the risk "
            "despite the organization identity record."
        )

    elif (
        identity.get(
            "matched",
            False,
        )
        and identity_state
        in positive_identity_states
        and requested_adjustment < 0
    ):
        contradictory_evidence = any(
            [
                strong_signal_count >= 1,
                brand_impersonation,
                original_score >= 70,
            ]
        )

        if contradictory_evidence:
            adjustment_blocked = True

            adjustment_reason = (
                "Positive organization identity evidence was "
                "not allowed to reduce risk because independent "
                "phishing indicators were present."
            )

        else:
            applied_adjustment = requested_adjustment

            adjustment_reason = (
                "Source-backed organization identity evidence "
                "reduced uncertainty because no contradictory "
                "phishing indicators were present."
            )

    elif not identity.get(
        "matched",
        False,
    ):
        adjustment_reason = (
            "No organization-domain match was found. Unknown "
            "identity added no risk and provided no trust bonus."
        )

    adjusted_score = clamp(
        original_score
        + applied_adjustment
    )

    # Verified established organizations with no strong phishing
    # evidence should not remain GUARDED solely because the legacy
    # ML model is overconfident.
    if (
        identity_state
        == "VERIFIED_ESTABLISHED"
        and security_state
        in {
            "CLEAN",
            "NEUTRAL",
        }
        and strong_signal_count == 0
        and not brand_impersonation
        and not adjustment_blocked
    ):
        adjusted_score = min(
            adjusted_score,
            18.0,
        )

    adjusted_score = round(
        adjusted_score,
        2,
    )

    risk_level = determine_risk_level(
        adjusted_score
    )

    classification = classify_score(
        adjusted_score
    )

    confidence = float(
        result.get(
            "confidence_percentage",
            0.0,
        )
        or 0.0
    )

    identity_confidence = float(
        identity.get(
            "identity_confidence",
            0.0,
        )
        or 0.0
    )

    if identity.get(
        "matched",
        False,
    ):
        confidence = max(
            confidence,
            min(
                95.0,
                (
                    confidence * 0.45
                    + identity_confidence * 0.55
                ),
            ),
        )

    confidence = round(
        clamp(
            confidence,
            0,
            99,
        ),
        2,
    )

    reasons = list(
        result.get(
            "reasons",
            [],
        )
    )

    for reason in identity.get(
        "reasons",
        [],
    ):
        if reason not in reasons:
            reasons.append(
                reason
            )

    reasons.append(
        adjustment_reason
    )

    updated = dict(
        result
    )

    updated.update(
        {
            "final_score_before_organization_intelligence": (
                original_score
            ),
            "final_score": adjusted_score,
            "confidence_percentage": confidence,
            "confidence_level": (
                "high"
                if confidence >= 80
                else (
                    "medium"
                    if confidence >= 60
                    else "low"
                )
            ),
            "risk_level": risk_level,
            "classification": classification,
            "is_suspicious": (
                adjusted_score >= 35
            ),
            "is_phishing": (
                adjusted_score >= 70
            ),
            "recommendation": (
                recommendation_for_score(
                    adjusted_score
                )
            ),
            "reasons": reasons,
            "organization_intelligence": {
                **identity,
                "hostname": normalized_hostname,
                "requested_score_adjustment": (
                    requested_adjustment
                ),
                "applied_score_adjustment": (
                    applied_adjustment
                ),
                "adjustment_blocked": (
                    adjustment_blocked
                ),
                "adjustment_reason": (
                    adjustment_reason
                ),
            },
        }
    )

    return updated
