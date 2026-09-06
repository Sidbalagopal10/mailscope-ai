from __future__ import annotations

from typing import Any

from app.global_entity_registry.identity.explanation import (
    explain_identity,
)


def shadow_identity_summary(
    value: str,
) -> dict[str, Any]:
    identity = explain_identity(
        value
    )

    best = identity.get(
        "best_match"
    )

    if not best:
        return {
            "input": value,
            "identity_known": False,
            "organization": None,
            "identity_state": "unknown",
            "identity_confidence": 0.0,
            "identity_band": "very_low",
            "web_presence_mode": (
                identity.get(
                    "web_presence",
                    {}
                ).get(
                    "mode"
                )
            ),
        }

    return {
        "input": value,

        "identity_known": (
            identity[
                "identity_known"
            ]
        ),

        "organization": (
            best.get(
                "organization"
            )
        ),

        "identity_state": (
            best.get(
                "evidence_state"
            )
        ),

        "identity_confidence": (
            best.get(
                "confidence_score"
            )
        ),

        "identity_band": (
            best.get(
                "confidence_band"
            )
        ),

        "web_presence_mode": (
            identity.get(
                "web_presence",
                {}
            ).get(
                "mode"
            )
        ),
    }
