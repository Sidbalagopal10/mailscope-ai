from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any

from app.services.risk_engine import analyze_url


def _read(
    value: Any,
    name: str,
    default=None,
):
    if isinstance(
        value,
        dict,
    ):
        return value.get(
            name,
            default,
        )

    return getattr(
        value,
        name,
        default,
    )


def run_live_detector(
    url: str,
) -> dict[str, Any]:
    """
    Call the CURRENT detector directly.

    Important:
    This deliberately calls app.services.risk_engine.analyze_url
    instead of GET /analyze-url.

    The HTTP endpoint saves a ScanResult to the application DB.
    This adapter does NOT do that.
    """

    result = analyze_url(
        url
    )

    reasons = _read(
        result,
        "reasons",
        [],
    )

    if reasons is None:
        reasons = []

    if isinstance(
        reasons,
        str,
    ):
        reasons = [
            reasons,
        ]

    severity = _read(
        result,
        "severity",
    )

    risk_level = _read(
        result,
        "risk_level",
    )

    suspicious = _read(
        result,
        "is_suspicious",
    )

    return {
        "url": (
            _read(
                result,
                "url",
                url,
            )
        ),

        "severity": (
            severity
        ),

        "risk_level": (
            risk_level
        ),

        "is_suspicious": (
            suspicious
        ),

        "reasons": list(
            reasons
        ),
    }
