from __future__ import annotations

from typing import Any


def threatfox_risk_evidence(
    observation: dict[str, Any] | None,
) -> dict[str, Any]:
    if not observation:
        return {
            "available": False,
            "matched": False,
            "risk_adjustment": 0.0,
            "confidence_adjustment": 0.0,
            "strong_signals": [],
            "reasons": [
                "No ThreatFox observation is available."
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
            "reasons": [
                (
                    "ThreatFox was unavailable. An API failure "
                    "does not make the indicator suspicious."
                )
            ],
        }

    if not observation.get(
        "matched"
    ):
        return {
            "available": True,
            "matched": False,
            "risk_adjustment": 0.0,
            "confidence_adjustment": 2.0,
            "strong_signals": [],
            "reasons": [
                (
                    "No active ThreatFox IOC match was found. "
                    "This does not prove that the indicator is safe."
                )
            ],
        }

    confidence = int(
        observation.get(
            "maximum_confidence",
            0,
        )
        or 0
    )

    match_count = int(
        observation.get(
            "match_count",
            0,
        )
        or 0
    )

    adjustment = 35.0

    if confidence >= 90:
        adjustment += 20

    elif confidence >= 70:
        adjustment += 15

    elif confidence >= 50:
        adjustment += 10

    else:
        adjustment += 5

    if match_count >= 3:
        adjustment += 5

    adjustment = min(
        adjustment,
        65.0,
    )

    malware_families = observation.get(
        "malware_families",
        [],
    )

    threat_types = observation.get(
        "threat_types",
        [],
    )

    description_parts = []

    if malware_families:
        description_parts.append(
            "Malware families: "
            + ", ".join(
                malware_families[:10]
            )
        )

    if threat_types:
        description_parts.append(
            "Threat types: "
            + ", ".join(
                threat_types[:10]
            )
        )

    return {
        "available": True,
        "matched": True,
        "risk_adjustment": round(
            adjustment,
            2,
        ),
        "confidence_adjustment": 18.0,
        "strong_signals": [
            (
                "ThreatFox reports the indicator as "
                "malware-associated infrastructure"
            )
        ],
        "reasons": [
            (
                "ThreatFox returned one or more active "
                "malware-related IOC matches."
            ),
            *description_parts,
        ],
        "malware_families": malware_families,
        "threat_types": threat_types,
        "maximum_confidence": confidence,
        "match_count": match_count,
        "important_limitations": [
            (
                "ThreatFox focuses on malware-associated IOCs, "
                "not every phishing campaign."
            ),
            (
                "No match does not prove that an indicator is safe."
            ),
            (
                "Shared cloud infrastructure can change owners; "
                "indicator age and current context still matter."
            ),
        ],
    }
