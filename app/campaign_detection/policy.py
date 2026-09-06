from __future__ import annotations


ARTIFACT_WEIGHTS = {
    "sha256": 1.00,
    "sha1": 0.95,
    "md5": 0.90,

    "url": 0.80,
    "email": 0.75,
    "domain": 0.60,

    # Shared IP infrastructure alone is intentionally weak.
    "ip": 0.45,
}


def artifact_weight(
    artifact_type: str,
) -> float:
    return float(
        ARTIFACT_WEIGHTS.get(
            artifact_type,
            0.0,
        )
    )


def relationship_rationale(
    artifact_type: str,
) -> str:
    messages = {
        "sha256": "Same SHA-256 observable.",
        "sha1": "Same SHA-1 observable.",
        "md5": "Same MD5 observable.",
        "url": "Same exact normalized URL.",
        "email": "Same normalized email observable.",
        "domain": "Same normalized domain or hostname.",
        "ip": (
            "Same IP address. Shared IP infrastructure alone "
            "is weak campaign evidence."
        ),
    }

    return messages.get(
        artifact_type,
        "Shared evidence-backed observable.",
    )


def score_strength(
    score: float,
) -> str:
    if score >= 0.85:
        return "strong"

    if score >= 0.60:
        return "moderate"

    return "weak"
