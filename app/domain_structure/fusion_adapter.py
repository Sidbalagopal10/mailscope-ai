from __future__ import annotations

from app.domain_structure.structure_engine import (
    analyze_structure,
)
from app.evidence_fusion.models import (
    Evidence,
    EvidenceDirection,
    EvidenceFamily,
    EvidenceStrength,
)


def structure_evidence(
    value: str,
) -> list[Evidence]:
    analysis = analyze_structure(
        value
    )

    score = float(
        analysis.get(
            "score",
            0.0,
        )
        or 0.0
    )

    if score < 8:
        return []

    if score >= 32:
        strength = (
            EvidenceStrength.STRONG
        )

    elif score >= 18:
        strength = (
            EvidenceStrength.MODERATE
        )

    else:
        strength = (
            EvidenceStrength.WEAK
        )

    reasons = [
        item[
            "reason"
        ]
        for item in analysis.get(
            "findings",
            [],
        )
    ]

    return [
        Evidence(
            source="domain_structure_v2",
            family=EvidenceFamily.BEHAVIOR,
            direction=EvidenceDirection.MALICIOUS,
            strength=strength,
            confidence=max(
                0.45,
                float(
                    analysis.get(
                        "confidence",
                        0.0,
                    )
                ),
            ),
            signal="suspicious_domain_structure",
            reason=(
                "Structural URL analysis found "
                f"{analysis['finding_count']} "
                "suspicious characteristic(s)."
            ),
            exact_relevance=True,
            independent_group=(
                "domain_structure"
            ),
            metadata={
                "structural_score": score,
                "findings": reasons,
            },
        )
    ]
