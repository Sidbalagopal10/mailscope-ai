from __future__ import annotations

from typing import Any

from app.benchmarking.urlhaus_index import (
    exact_lookup,
)
from app.domain_structure.fusion_adapter import (
    structure_evidence,
)
from app.evidence_fusion.adapters import (
    identity_evidence,
    impersonation_evidence,
    urlhaus_exact_evidence,
)
from app.evidence_fusion.engine import (
    fuse_evidence,
)
from app.evidence_fusion.models import (
    Evidence,
    EvidenceDirection,
    EvidenceFamily,
    EvidenceStrength,
)
from app.global_entity_registry.source_agreement import (
    evaluate_domain_identity,
)


SUSPICIOUS_TERMS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "password",
    "wallet",
    "billing",
    "update",
    "confirm",
    "auth",
}


BRANDS = {
    "google",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "github",
    "linkedin",
    "netflix",
    "facebook",
    "instagram",
    "nvidia",
}


def lexical_evidence(
    value: str,
) -> list[Evidence]:
    lowered = value.lower()

    evidence = []

    matched_terms = [
        term
        for term in SUSPICIOUS_TERMS
        if term in lowered
    ]

    if matched_terms:
        evidence.append(
            Evidence(
                source="offline_url_lexical",
                family=EvidenceFamily.CONTENT,
                direction=EvidenceDirection.MALICIOUS,
                strength=EvidenceStrength.WEAK,
                confidence=0.60,
                signal="suspicious_url_terms",
                reason=(
                    "URL contains security-sensitive terms: "
                    + ", ".join(
                        sorted(
                            matched_terms
                        )[:5]
                    )
                ),
                independent_group="url_lexical",
            )
        )

    if "@" in value:
        evidence.append(
            Evidence(
                source="offline_url_lexical",
                family=EvidenceFamily.BEHAVIOR,
                direction=EvidenceDirection.MALICIOUS,
                strength=EvidenceStrength.MODERATE,
                confidence=0.80,
                signal="at_symbol_url",
                reason=(
                    "URL contains an @ symbol."
                ),
                independent_group="url_structure",
            )
        )

    if len(
        value
    ) >= 120:
        evidence.append(
            Evidence(
                source="offline_url_lexical",
                family=EvidenceFamily.CONTENT,
                direction=EvidenceDirection.MALICIOUS,
                strength=EvidenceStrength.WEAK,
                confidence=0.55,
                signal="very_long_url",
                reason=(
                    "URL is unusually long."
                ),
                independent_group="url_lexical",
            )
        )

    return evidence


def simple_brand_evidence(
    value: str,
    identity_state: str,
) -> list[Evidence]:
    lowered = value.lower()

    if identity_state in {
        "verified",
        "supported",
    }:
        return []

    for brand in BRANDS:
        if brand in lowered:
            return impersonation_evidence(
                detected=True,
                similarity=0.90,
                claimed_brand=brand.title(),
            )

    return []


def analyze_offline(
    value: str,
) -> dict[str, Any]:
    identity = evaluate_domain_identity(
        value
    )

    identity_state = str(
        identity.get(
            "identity_state",
            "unknown",
        )
    )

    evidence = []

    evidence += identity_evidence(
        identity
    )

    evidence += lexical_evidence(
        value
    )

    evidence += structure_evidence(
        value
    )

    evidence += simple_brand_evidence(
        value,
        identity_state,
    )

    urlhaus = exact_lookup(
        value
    )

    evidence += urlhaus_exact_evidence(
        matched=urlhaus[
            "matched"
        ],
        match_type=urlhaus[
            "match_type"
        ],
    )

    fusion = fuse_evidence(
        evidence,
        identity_state=identity_state,
    )

    return {
        "risk_score": fusion.risk_score,
        "risk_level": fusion.risk_level,
        "verdict": fusion.verdict,
        "confidence": fusion.confidence,
        "identity_state": identity_state,

        "urlhaus": urlhaus,

        "safeguards": (
            fusion.safeguards_triggered
        ),

        "contributions": (
            fusion.contributions
        ),
    }
