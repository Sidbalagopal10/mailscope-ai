from __future__ import annotations

from app.evidence_fusion.models import (
    Evidence,
    EvidenceDirection,
    EvidenceFamily,
    EvidenceStrength,
)
from app.rdap_intelligence.client import (
    analyze_domain,
)


def rdap_evidence(
    value: str,
) -> tuple[
    list[Evidence],
    dict,
]:
    result = analyze_domain(
        value
    )

    if result.get(
        "status"
    ) != "success":
        return (
            [],
            result,
        )

    age_days = result.get(
        "domain_age_days"
    )

    if age_days is None:
        return (
            [],
            result,
        )

    evidence = []

    if age_days <= 3:
        evidence.append(
            Evidence(
                source="RDAP",
                family=EvidenceFamily.INFRASTRUCTURE,
                direction=EvidenceDirection.MALICIOUS,
                strength=EvidenceStrength.STRONG,
                confidence=0.88,
                signal="extremely_new_domain",
                reason=(
                    "RDAP indicates the domain was "
                    f"registered approximately {age_days} "
                    "day(s) ago."
                ),
                independent_group="rdap_lifecycle",
            )
        )

    elif age_days <= 14:
        evidence.append(
            Evidence(
                source="RDAP",
                family=EvidenceFamily.INFRASTRUCTURE,
                direction=EvidenceDirection.MALICIOUS,
                strength=EvidenceStrength.MODERATE,
                confidence=0.82,
                signal="very_new_domain",
                reason=(
                    "RDAP indicates the domain was "
                    f"registered approximately {age_days} "
                    "days ago."
                ),
                independent_group="rdap_lifecycle",
            )
        )

    elif age_days <= 60:
        evidence.append(
            Evidence(
                source="RDAP",
                family=EvidenceFamily.INFRASTRUCTURE,
                direction=EvidenceDirection.MALICIOUS,
                strength=EvidenceStrength.WEAK,
                confidence=0.68,
                signal="new_domain",
                reason=(
                    "RDAP indicates the domain was "
                    f"registered approximately {age_days} "
                    "days ago."
                ),
                independent_group="rdap_lifecycle",
            )
        )

    elif age_days >= 3650:
        evidence.append(
            Evidence(
                source="RDAP",
                family=EvidenceFamily.INFRASTRUCTURE,
                direction=EvidenceDirection.BENIGN,
                strength=EvidenceStrength.WEAK,
                confidence=0.78,
                signal="long_lived_domain",
                reason=(
                    "RDAP indicates the domain has existed "
                    "for roughly ten years or longer."
                ),
                independent_group="rdap_lifecycle",
            )
        )

    return (
        evidence,
        result,
    )
