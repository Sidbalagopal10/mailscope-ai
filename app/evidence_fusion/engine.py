from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from app.evidence_fusion.models import (
    Evidence,
    EvidenceDirection,
    EvidenceFamily,
    EvidenceStrength,
    FusionResult,
)
from app.evidence_fusion.policy import (
    base_weight,
)


def clamp(
    value: float,
    minimum: float = 0.0,
    maximum: float = 100.0,
) -> float:
    return max(
        minimum,
        min(
            float(value),
            maximum,
        ),
    )


def risk_level(
    score: float,
) -> str:
    if score >= 80:
        return "critical"

    if score >= 60:
        return "high"

    if score >= 35:
        return "moderate"

    return "low"


def verdict_for_score(
    score: float,
) -> str:
    if score >= 80:
        return "likely_malicious"

    if score >= 60:
        return "high_risk"

    if score >= 35:
        return "needs_review"

    return "likely_legitimate"


def evidence_contribution(
    evidence: Evidence,
) -> float:
    if not evidence.exact_relevance:
        return 0.0

    confidence = clamp(
        evidence.confidence,
        0.0,
        1.0,
    )

    return round(
        base_weight(
            evidence.direction,
            evidence.strength,
        )
        * confidence,
        2,
    )


def fuse_evidence(
    evidence_items: Iterable[Evidence],
    *,
    identity_state: str | None = None,
) -> FusionResult:
    evidence = list(
        evidence_items
    )

    contributions = []
    explanations = []
    safeguards = []

    malicious = []
    benign = []
    neutral = []

    malicious_families = set()
    malicious_groups = set()

    score = 0.0

    for item in evidence:
        contribution = evidence_contribution(
            item
        )

        if item.direction == EvidenceDirection.MALICIOUS:
            malicious.append(
                item
            )

            if (
                item.exact_relevance
                and contribution > 0
            ):
                malicious_families.add(
                    item.family.value
                )

                malicious_groups.add(
                    item.independent_group
                    or item.source
                )

        elif item.direction == EvidenceDirection.BENIGN:
            benign.append(
                item
            )

        else:
            neutral.append(
                item
            )

        score += contribution

        contributions.append(
            {
                "source": item.source,
                "family": item.family.value,
                "direction": item.direction.value,
                "strength": item.strength.value,
                "confidence": round(
                    float(
                        item.confidence
                    ),
                    3,
                ),
                "exact_relevance": (
                    item.exact_relevance
                ),
                "contribution": contribution,
                "signal": item.signal,
                "reason": item.reason,
            }
        )

        if item.reason:
            explanations.append(
                item.reason
            )

    score = max(
        0.0,
        score,
    )

    # ----------------------------------------------
    # SAFEGUARD 1:
    # irrelevant reputation evidence contributes 0.
    # ----------------------------------------------
    irrelevant_malicious = [
        item
        for item in malicious
        if not item.exact_relevance
    ]

    if irrelevant_malicious:
        safeguards.append(
            "irrelevant_reputation_evidence_filtered"
        )

    # ----------------------------------------------
    # SAFEGUARD 2:
    # one malicious source cannot create High/Critical
    # unless the signal itself is critical and exact.
    # ----------------------------------------------
    relevant_malicious = [
        item
        for item in malicious
        if item.exact_relevance
    ]

    critical_exact = any(
        item.strength
        == EvidenceStrength.CRITICAL
        and item.confidence >= 0.90
        for item in relevant_malicious
    )

    if (
        len(
            malicious_groups
        )
        <= 1
        and not critical_exact
        and score >= 60
    ):
        score = min(
            score,
            49.0,
        )

        safeguards.append(
            "single_source_high_risk_cap"
        )

    # ----------------------------------------------
    # SAFEGUARD 3:
    # High/Critical normally requires corroboration
    # across at least two evidence families.
    # ----------------------------------------------
    if (
        len(
            malicious_families
        )
        < 2
        and not critical_exact
        and score >= 60
    ):
        score = min(
            score,
            49.0,
        )

        safeguards.append(
            "cross_family_corroboration_required"
        )

    # ----------------------------------------------
    # SAFEGUARD 4:
    # verified identity suppresses weak isolated
    # reputation noise, but never overrides strong,
    # corroborated malicious evidence.
    # ----------------------------------------------
    if identity_state == "verified":
        strong_malicious = [
            item
            for item in relevant_malicious
            if item.strength
            in {
                EvidenceStrength.STRONG,
                EvidenceStrength.CRITICAL,
            }
            and item.confidence >= 0.75
        ]

        if (
            len(
                strong_malicious
            )
            == 0
            and score >= 35
        ):
            score = min(
                score,
                24.0,
            )

            safeguards.append(
                "verified_identity_weak_noise_guard"
            )

    # ----------------------------------------------
    # SAFEGUARD 5:
    # unknown identity is neutral.
    # ----------------------------------------------
    if identity_state == "unknown":
        safeguards.append(
            "unknown_identity_neutral"
        )

    score = round(
        clamp(
            score
        ),
        2,
    )

    # Confidence is based on amount, diversity and quality
    # of relevant evidence rather than the risk score itself.
    relevant = [
        item
        for item in evidence
        if item.exact_relevance
        and item.direction
        != EvidenceDirection.NEUTRAL
    ]

    if not relevant:
        confidence = 0.35

    else:
        average = sum(
            clamp(
                item.confidence,
                0.0,
                1.0,
            )
            for item in relevant
        ) / len(
            relevant
        )

        diversity_bonus = min(
            0.20,
            0.05
            * len(
                {
                    item.family.value
                    for item in relevant
                }
            ),
        )

        confidence = min(
            0.99,
            average
            + diversity_bonus,
        )

    return FusionResult(
        risk_score=score,
        confidence=round(
            confidence,
            3,
        ),
        verdict=verdict_for_score(
            score
        ),
        risk_level=risk_level(
            score
        ),
        malicious_evidence_count=len(
            malicious
        ),
        benign_evidence_count=len(
            benign
        ),
        neutral_evidence_count=len(
            neutral
        ),
        corroborating_malicious_families=len(
            malicious_families
        ),
        contributions=contributions,
        explanations=list(
            dict.fromkeys(
                explanations
            )
        ),
        safeguards_triggered=list(
            dict.fromkeys(
                safeguards
            )
        ),
        identity_state=identity_state,
    )
