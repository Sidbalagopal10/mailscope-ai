from __future__ import annotations

from typing import Any

from app.benchmarking.structural_features import (
    extract_structural_features,
)
from app.evidence_fusion.models import (
    Evidence,
    EvidenceDirection,
    EvidenceFamily,
    EvidenceStrength,
)


def shared_host_corroboration(
    *,
    value: str,
    hosting: dict[str, Any],
    identity_state: str,
) -> list[Evidence]:
    if not hosting.get(
        "matched"
    ):
        return []

    if not hosting.get(
        "user_generated"
    ):
        return []

    if identity_state in {
        "verified",
        "supported",
    }:
        return []

    features = extract_structural_features(
        value
    )

    brand_count = int(
        features.get(
            "brand_token_count",
            0,
        )
        or 0
    )

    sensitive_count = int(
        features.get(
            "sensitive_term_count",
            0,
        )
        or 0
    )

    if (
        brand_count >= 1
        and sensitive_count >= 1
    ):
        return [
            Evidence(
                source="hosting_corroboration",
                family=EvidenceFamily.BEHAVIOR,
                direction=EvidenceDirection.MALICIOUS,
                strength=EvidenceStrength.STRONG,
                confidence=0.88,
                signal=(
                    "brand_credential_activity_"
                    "on_shared_host"
                ),
                reason=(
                    "An unknown organization is using a "
                    "user-generated hosting platform while "
                    "the URL contains both recognizable "
                    "brand references and credential/security "
                    "language."
                ),
                exact_relevance=True,
                independent_group=(
                    "hosting_behavior_corroboration"
                ),
                metadata={
                    "provider": hosting.get(
                        "provider"
                    ),
                    "platform": hosting.get(
                        "platform"
                    ),
                    "brand_tokens": features.get(
                        "brand_tokens"
                    ),
                    "sensitive_terms": features.get(
                        "sensitive_terms"
                    ),
                },
            )
        ]

    if brand_count >= 1:
        return [
            Evidence(
                source="hosting_corroboration",
                family=EvidenceFamily.BEHAVIOR,
                direction=EvidenceDirection.MALICIOUS,
                strength=EvidenceStrength.MODERATE,
                confidence=0.72,
                signal=(
                    "brand_reference_on_shared_host"
                ),
                reason=(
                    "An unknown identity references a known "
                    "brand while using user-generated hosting."
                ),
                exact_relevance=True,
                independent_group=(
                    "hosting_behavior_corroboration"
                ),
            )
        ]

    return []
