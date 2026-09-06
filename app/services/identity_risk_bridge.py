from __future__ import annotations

from typing import Any

from app.evidence_fusion.identity_aware_policy import (
    evaluate_identity_aware_candidate,
)
from app.global_entity_registry.identity.shadow import (
    shadow_identity_summary,
)


def apply_identity_risk_policy(
    *,
    url: str,
    severity: float,
    is_suspicious: bool,
    reasons: list[str],
) -> dict[str, Any]:
    """
    Core v1.0 identity-risk bridge.

    Identity itself never establishes maliciousness.

    The bridge only escalates when:
      - identity is unknown
      - existing detector sees impersonation
      - another corroborating contextual signal exists
    """

    try:
        identity = shadow_identity_summary(
            url
        )

    except Exception as error:
        # Fail open with respect to identity intelligence.
        # Existing detector result remains authoritative
        # if identity lookup is unavailable.
        return {
            "severity": float(
                severity
            ),

            "is_suspicious": bool(
                is_suspicious
            ),

            "reasons": list(
                reasons
            ),

            "identity": {
                "state": "unavailable",
                "error": (
                    f"{type(error).__name__}: "
                    f"{error}"
                ),
            },

            "identity_escalation": False,
        }

    decision = evaluate_identity_aware_candidate(
        url=url,
        severity=severity,
        is_suspicious=is_suspicious,
        legacy_reasons=reasons,
        identity_state=identity.get(
            "identity_state",
            "unknown",
        ),
    )

    return {
        "severity": (
            decision.candidate_severity
        ),

        "is_suspicious": (
            decision.candidate_suspicious
        ),

        "reasons": list(
            decision.reasons
        ),

        "identity": {
            "known": identity.get(
                "identity_known"
            ),

            "organization": identity.get(
                "organization"
            ),

            "state": identity.get(
                "identity_state"
            ),

            "confidence": identity.get(
                "identity_confidence"
            ),

            "band": identity.get(
                "identity_band"
            ),

            "web_presence_mode": identity.get(
                "web_presence_mode"
            ),
        },

        "identity_escalation": (
            decision.escalation_applied
        ),
    }
