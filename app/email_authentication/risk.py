from __future__ import annotations

from typing import Any


def authentication_risk_evidence(
    authentication: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Produce bounded evidence.

    Authentication success verifies message-handling identities.
    It does not prove that the sender's account is uncompromised
    or that the request itself is harmless.
    """
    if not authentication:
        return {
            "available": False,
            "risk_adjustment": 0.0,
            "confidence_adjustment": 0.0,
            "verdict": "unavailable",
            "positive_signals": [],
            "weak_signals": [],
            "strong_signals": [],
            "reasons": [
                "No email authentication headers were available."
            ],
        }

    spf = authentication.get(
        "spf",
        {},
    ).get(
        "result",
        "unknown",
    )

    dkim = authentication.get(
        "dkim",
        {},
    ).get(
        "result",
        "unknown",
    )

    dmarc = authentication.get(
        "dmarc",
        {},
    ).get(
        "result",
        "unknown",
    )

    arc = authentication.get(
        "arc",
        {},
    ).get(
        "result",
        "unknown",
    )

    positive_signals: list[str] = []
    weak_signals: list[str] = []
    strong_signals: list[str] = []
    reasons: list[str] = []

    adjustment = 0.0
    confidence_adjustment = 0.0

    if dmarc == "pass":
        positive_signals.append(
            "DMARC passed"
        )
        adjustment -= 5.0
        confidence_adjustment += 8.0

    elif dmarc in {
        "fail",
        "hardfail",
        "permerror",
    }:
        strong_signals.append(
            "DMARC failed"
        )
        adjustment += 24.0
        confidence_adjustment += 8.0

    elif dmarc == "temperror":
        weak_signals.append(
            "DMARC produced a temporary error"
        )
        adjustment += 1.0

    if dkim == "pass":
        positive_signals.append(
            "DKIM passed"
        )
        adjustment -= 2.0
        confidence_adjustment += 4.0

    elif dkim in {
        "fail",
        "hardfail",
        "permerror",
    }:
        weak_signals.append(
            "DKIM failed"
        )
        adjustment += 5.0

    if spf == "pass":
        positive_signals.append(
            "SPF passed"
        )
        adjustment -= 1.0
        confidence_adjustment += 2.0

    elif spf in {
        "fail",
        "hardfail",
    }:
        # SPF failure alone is weak because forwarding can break it.
        weak_signals.append(
            "SPF failed"
        )
        adjustment += 4.0

    elif spf == "softfail":
        weak_signals.append(
            "SPF soft-failed"
        )
        adjustment += 2.0

    if arc == "pass":
        positive_signals.append(
            "ARC passed"
        )
        confidence_adjustment += 2.0

        if (
            spf in {
                "fail",
                "softfail",
                "hardfail",
            }
            and dkim == "pass"
        ):
            adjustment = max(
                adjustment - 3.0,
                -8.0,
            )

            reasons.append(
                "ARC and DKIM evidence reduce concern from "
                "an isolated SPF failure, which may result "
                "from forwarding."
            )

    triple_failure = (
        spf in {
            "fail",
            "hardfail",
            "softfail",
        }
        and dkim in {
            "fail",
            "hardfail",
            "permerror",
        }
        and dmarc in {
            "fail",
            "hardfail",
            "permerror",
        }
    )

    if triple_failure:
        adjustment = max(
            adjustment,
            38.0,
        )

        strong_signals.append(
            "SPF, DKIM, and DMARC all failed"
        )

        reasons.append(
            "Multiple independent sender-authentication "
            "mechanisms failed."
        )

    available = any(
        result not in {
            "unknown",
            "none",
        }
        for result in (
            spf,
            dkim,
            dmarc,
            arc,
        )
    )

    if not available:
        verdict = "unknown"
        adjustment = 0.0

        reasons.append(
            "No conclusive authentication result was found. "
            "Absence of results does not prove phishing."
        )

    elif triple_failure:
        verdict = "authentication_failed"

    elif dmarc == "pass":
        verdict = "authenticated"

    elif dmarc in {
        "fail",
        "hardfail",
        "permerror",
    }:
        verdict = "dmarc_failed"

    else:
        verdict = "mixed"

    return {
        "available": available,
        "verdict": verdict,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "arc": arc,
        "risk_adjustment": round(
            max(
                -8.0,
                min(
                    adjustment,
                    45.0,
                ),
            ),
            2,
        ),
        "confidence_adjustment": round(
            min(
                confidence_adjustment,
                15.0,
            ),
            2,
        ),
        "positive_signals": positive_signals,
        "weak_signals": weak_signals,
        "strong_signals": strong_signals,
        "reasons": reasons,
        "important_limitations": [
            (
                "Authentication pass does not prove that the "
                "sender account is uncompromised."
            ),
            (
                "SPF failure alone can occur when a message "
                "is forwarded."
            ),
            (
                "Authentication does not determine whether "
                "an urgent request is appropriate."
            ),
            (
                "Sender behavior, conversation context, links, "
                "attachments, and requested actions still require analysis."
            ),
        ],
    }
