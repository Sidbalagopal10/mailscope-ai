from __future__ import annotations

from app.evidence_fusion.models import (
    EvidenceDirection,
    EvidenceStrength,
)


MALICIOUS_WEIGHTS = {
    EvidenceStrength.WEAK: 8.0,
    EvidenceStrength.MODERATE: 18.0,
    EvidenceStrength.STRONG: 32.0,
    EvidenceStrength.CRITICAL: 50.0,
}

BENIGN_WEIGHTS = {
    EvidenceStrength.WEAK: -3.0,
    EvidenceStrength.MODERATE: -8.0,
    EvidenceStrength.STRONG: -15.0,
    EvidenceStrength.CRITICAL: -20.0,
}


def base_weight(
    direction: EvidenceDirection,
    strength: EvidenceStrength,
) -> float:
    if direction == EvidenceDirection.MALICIOUS:
        return MALICIOUS_WEIGHTS[
            strength
        ]

    if direction == EvidenceDirection.BENIGN:
        return BENIGN_WEIGHTS[
            strength
        ]

    return 0.0
