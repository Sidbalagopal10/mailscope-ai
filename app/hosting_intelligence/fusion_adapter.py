from __future__ import annotations

from typing import Any

from app.evidence_fusion.models import (
    Evidence,
    EvidenceDirection,
    EvidenceFamily,
    EvidenceStrength,
)
from app.hosting_intelligence.matcher import (
    identify_hosting,
)


def hosting_evidence(
    value: str,
) -> tuple[
    list[Evidence],
    dict[str, Any],
]:
    result = identify_hosting(
        value
    )

    if not result.get(
        "matched"
    ):
        return (
            [],
            result,
        )

    provider = result.get(
        "provider"
    )

    platform = result.get(
        "platform"
    )

    return (
        [
            Evidence(
                source="hosting_intelligence",
                family=EvidenceFamily.INFRASTRUCTURE,
                direction=EvidenceDirection.NEUTRAL,
                strength=EvidenceStrength.WEAK,
                confidence=0.95,
                signal="shared_hosting_platform",
                reason=(
                    f"The URL is hosted on {platform} "
                    f"operated by {provider}. "
                    "Shared hosting is neutral and requires "
                    "corroborating evidence."
                ),
                exact_relevance=True,
                independent_group="hosting_platform",
                metadata=result,
            )
        ],
        result,
    )
