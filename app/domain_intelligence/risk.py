from __future__ import annotations

from typing import Any


def rdap_risk_evidence(
    observation: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Convert RDAP facts into bounded evidence.

    Domain age is never enough by itself to declare a domain
    malicious or legitimate.
    """
    if not observation:
        return {
            "available": False,
            "risk_adjustment": 0.0,
            "confidence_adjustment": 0.0,
            "strong_signals": [],
            "weak_signals": [],
            "positive_signals": [],
            "reasons": [
                "No RDAP observation is available."
            ],
        }

    if observation.get(
        "lookup_status"
    ) != "success":
        return {
            "available": False,
            "risk_adjustment": 0.0,
            "confidence_adjustment": 0.0,
            "strong_signals": [],
            "weak_signals": [],
            "positive_signals": [],
            "reasons": [
                (
                    "RDAP data was unavailable. This does not "
                    "make the domain malicious."
                )
            ],
        }

    strong_signals = []
    weak_signals = []
    positive_signals = []
    reasons = []
    adjustment = 0.0
    confidence_adjustment = 4.0

    age_days = observation.get(
        "domain_age_days"
    )

    if age_days is not None:
        age_days = int(
            age_days
        )

        if age_days <= 3:
            weak_signals.append(
                "Domain registered within the last 3 days"
            )

            reasons.append(
                "The domain is extremely new, but age alone "
                "does not prove malicious intent."
            )

            adjustment += 6.0

        elif age_days <= 30:
            weak_signals.append(
                "Domain registered within the last 30 days"
            )

            reasons.append(
                "The domain has limited registration history."
            )

            adjustment += 3.0

        elif age_days >= 3650:
            positive_signals.append(
                "Domain registration history exceeds 10 years"
            )

            reasons.append(
                "The domain has a long registration history."
            )

            adjustment -= 3.0

        elif age_days >= 730:
            positive_signals.append(
                "Domain registration history exceeds 2 years"
            )

            adjustment -= 1.0

    statuses = {
        str(status).lower()
        for status in observation.get(
            "domain_status",
            []
        )
    }

    if any(
        phrase in status
        for status in statuses
        for phrase in {
            "server hold",
            "client hold",
        }
    ):
        strong_signals.append(
            "Registry or registrar hold status"
        )

        reasons.append(
            "The domain has a hold status that may prevent "
            "normal DNS publication."
        )

        adjustment += 15.0

    if observation.get(
        "dnssec_state"
    ) == "signed":
        positive_signals.append(
            "DNSSEC delegation is signed"
        )

        confidence_adjustment += 2.0

    if observation.get(
        "registrar_name"
    ):
        positive_signals.append(
            "Registrar identity is available"
        )

    return {
        "available": True,
        "risk_adjustment": round(
            max(
                -5.0,
                min(
                    adjustment,
                    20.0,
                ),
            ),
            2,
        ),
        "confidence_adjustment": round(
            confidence_adjustment,
            2,
        ),
        "strong_signals": strong_signals,
        "weak_signals": weak_signals,
        "positive_signals": positive_signals,
        "reasons": reasons,
    }
