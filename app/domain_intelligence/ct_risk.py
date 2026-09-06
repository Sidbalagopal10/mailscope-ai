from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def parse_datetime(
    value: Any,
) -> datetime | None:
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(
            str(
                value
            ).replace(
                "Z",
                "+00:00",
            )
        )

    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(
        timezone.utc
    )


def certificate_transparency_evidence(
    summary: dict[str, Any] | None,
) -> dict[str, Any]:
    if not summary:
        return {
            "available": False,
            "risk_adjustment": 0.0,
            "confidence_adjustment": 0.0,
            "weak_signals": [],
            "positive_signals": [],
            "reasons": [
                "No Certificate Transparency "
                "observation is available."
            ],
        }

    if summary.get(
        "lookup_status"
    ) != "success":
        return {
            "available": False,
            "risk_adjustment": 0.0,
            "confidence_adjustment": 0.0,
            "weak_signals": [],
            "positive_signals": [],
            "reasons": [
                "Certificate Transparency data "
                "was unavailable. Missing data "
                "does not add risk."
            ],
        }

    adjustment = 0.0
    confidence_adjustment = 3.0
    weak_signals = []
    positive_signals = []
    reasons = []

    certificate_count = int(
        summary.get(
            "certificate_count",
            0,
        )
        or 0
    )

    first_seen = parse_datetime(
        summary.get(
            "first_seen"
        )
    )

    last_seen = parse_datetime(
        summary.get(
            "last_seen"
        )
    )

    now = datetime.now(
        timezone.utc
    )

    if first_seen is not None:
        first_seen_age = (
            now - first_seen
        ).days

        if first_seen_age <= 7:
            weak_signals.append(
                "First observed certificate "
                "within the last 7 days"
            )

            reasons.append(
                "The domain has very limited public "
                "certificate history. This alone does "
                "not prove phishing."
            )

            adjustment += 2.0

        elif first_seen_age >= 3650:
            positive_signals.append(
                "Public certificate history "
                "exceeds 10 years"
            )

            adjustment -= 2.0

        elif first_seen_age >= 730:
            positive_signals.append(
                "Public certificate history "
                "exceeds 2 years"
            )

            adjustment -= 1.0

    if certificate_count >= 5:
        positive_signals.append(
            "Multiple certificates appear "
            "in public CT history"
        )

        confidence_adjustment += 2.0

    if last_seen is not None:
        days_since_last_seen = (
            now - last_seen
        ).days

        if days_since_last_seen <= 90:
            positive_signals.append(
                "Recent certificate activity exists"
            )

    return {
        "available": True,
        "risk_adjustment": round(
            max(
                -3.0,
                min(
                    adjustment,
                    5.0,
                ),
            ),
            2,
        ),
        "confidence_adjustment": round(
            confidence_adjustment,
            2,
        ),
        "weak_signals": weak_signals,
        "positive_signals": positive_signals,
        "reasons": reasons,
    }
