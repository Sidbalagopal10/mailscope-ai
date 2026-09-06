from __future__ import annotations

from typing import Any

from app.organization_intelligence.store import (
    resolve_domain,
)


def identity_score_adjustment(
    hostname: str,
) -> dict[str, Any]:
    """
    Convert registry identity into bounded supporting evidence.

    Identity evidence can reduce uncertainty, but it cannot
    override current malicious behavior.
    """
    record = resolve_domain(
        hostname
    )

    if record is None:
        return {
            "matched": False,
            "identity_state": "UNKNOWN",
            "security_state": "NEUTRAL",
            "score_adjustment": 0.0,
            "identity_confidence": 0.0,
            "security_confidence": 0.0,
            "reasons": [
                (
                    "No organization-domain registry "
                    "match was found. Unknown identity "
                    "does not add risk."
                )
            ],
            "record": None,
        }

    identity_state = record[
        "identity_state"
    ]

    security_state = record[
        "security_state"
    ]

    adjustment = 0.0
    reasons = []

    if security_state == "KNOWN_MALICIOUS":
        adjustment += 45

        reasons.append(
            "The domain is recorded as known malicious."
        )

    elif security_state == "COMPROMISED_LEGITIMATE":
        adjustment += 35

        reasons.append(
            "The domain belongs to a legitimate entity "
            "but is recorded as compromised."
        )

    elif security_state == "SUSPICIOUS":
        adjustment += 20

        reasons.append(
            "The domain has suspicious security history."
        )

    elif identity_state == "VERIFIED_ESTABLISHED":
        adjustment -= 18

        reasons.append(
            "Multiple authoritative identity records "
            "associate this established organization "
            "with the domain."
        )

    elif identity_state == "VERIFIED_NEW":
        adjustment -= 8

        reasons.append(
            "The domain is associated with a verified "
            "new organization; its security history "
            "is still limited."
        )

    elif identity_state == "OBSERVED_LEGITIMATE":
        adjustment -= 6

        reasons.append(
            "The domain has repeated legitimate "
            "observations."
        )

    elif identity_state == "PROVISIONAL":
        adjustment -= 3

        reasons.append(
            "A provisional organization-domain "
            "association exists."
        )

    return {
        "matched": True,
        "identity_state": identity_state,
        "security_state": security_state,
        "score_adjustment": adjustment,
        "identity_confidence": float(
            record[
                "identity_confidence"
            ]
        ),
        "security_confidence": float(
            record[
                "security_confidence"
            ]
        ),
        "reasons": reasons,
        "record": record,
    }
