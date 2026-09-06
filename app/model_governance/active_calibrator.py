from __future__ import annotations

from typing import Any


def apply_active_calibrator(
    *,
    predicted_score: float,
    predicted_risk_level: str,
    predicted_classification: str,
) -> dict[str, Any]:
    """
    Safe fallback used when no promoted calibration model is active.

    The unified email pipeline can continue operating with the
    original detector score. No score or verdict is overridden.
    """
    score = float(
        predicted_score
        or 0.0
    )

    return {
        "available": False,
        "applied": False,
        "error": None,
        "reason": (
            "No promoted human-reviewed calibrator is active. "
            "The original detector remains authoritative."
        ),
        "original_score": round(
            score,
            2,
        ),
        "original_risk_level": str(
            predicted_risk_level
            or "unknown"
        ),
        "original_classification": str(
            predicted_classification
            or "unknown"
        ),
        "calibrated_probability": None,
        "calibrated_score": round(
            score,
            2,
        ),
        "candidate_prediction": None,
        "active_version": None,
        "advisory_only": True,
        "original_detector_overridden": False,
    }
