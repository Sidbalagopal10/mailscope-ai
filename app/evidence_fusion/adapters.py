from __future__ import annotations

from typing import Any

from app.evidence_fusion.models import (
    Evidence,
    EvidenceDirection,
    EvidenceFamily,
    EvidenceStrength,
)


def identity_evidence(
    identity_result: dict[str, Any],
) -> list[Evidence]:
    state = str(
        identity_result.get(
            "identity_state",
            "unknown",
        )
    ).lower()

    confidence = float(
        identity_result.get(
            "confidence",
            0.0,
        )
        or 0.0
    )

    entity = (
        identity_result.get(
            "entity"
        )
        or {}
    )

    name = entity.get(
        "name"
    )

    if state == "verified":
        return [
            Evidence(
                source="global_entity_registry",
                family=EvidenceFamily.IDENTITY,
                direction=EvidenceDirection.BENIGN,
                strength=EvidenceStrength.STRONG,
                confidence=max(
                    0.90,
                    confidence,
                ),
                signal="verified_official_identity",
                reason=(
                    f"Verified official identity"
                    + (
                        f" for {name}."
                        if name
                        else "."
                    )
                ),
                independent_group="identity_registry",
            )
        ]

    if state == "supported":
        return [
            Evidence(
                source="global_entity_registry",
                family=EvidenceFamily.IDENTITY,
                direction=EvidenceDirection.BENIGN,
                strength=EvidenceStrength.MODERATE,
                confidence=max(
                    0.60,
                    confidence,
                ),
                signal="supported_identity",
                reason=(
                    "The domain has supported official "
                    "identity evidence."
                ),
                independent_group="identity_registry",
            )
        ]

    if state == "conflicting":
        return [
            Evidence(
                source="global_entity_registry",
                family=EvidenceFamily.IDENTITY,
                direction=EvidenceDirection.NEUTRAL,
                strength=EvidenceStrength.MODERATE,
                confidence=0.50,
                signal="identity_conflict",
                reason=(
                    "Identity sources conflict about "
                    "the domain owner."
                ),
                independent_group="identity_registry",
            )
        ]

    return [
        Evidence(
            source="global_entity_registry",
            family=EvidenceFamily.IDENTITY,
            direction=EvidenceDirection.NEUTRAL,
            strength=EvidenceStrength.WEAK,
            confidence=0.35,
            signal="unknown_identity",
            reason=(
                "No verified official identity evidence "
                "was found."
            ),
            independent_group="identity_registry",
        )
    ]


def threatfox_evidence(
    *,
    matched: bool,
    exact_relevance: bool,
    confidence: float,
    ioc_count: int = 0,
) -> list[Evidence]:
    if not matched:
        return [
            Evidence(
                source="ThreatFox",
                family=EvidenceFamily.REPUTATION,
                direction=EvidenceDirection.NEUTRAL,
                strength=EvidenceStrength.WEAK,
                confidence=0.50,
                signal="no_relevant_ioc",
                reason=(
                    "ThreatFox provided no relevant IOC match."
                ),
                independent_group="threatfox",
            )
        ]

    return [
        Evidence(
            source="ThreatFox",
            family=EvidenceFamily.REPUTATION,
            direction=EvidenceDirection.MALICIOUS,
            strength=(
                EvidenceStrength.STRONG
                if exact_relevance
                else EvidenceStrength.WEAK
            ),
            confidence=confidence,
            signal="ioc_match",
            reason=(
                f"ThreatFox returned {ioc_count} IOC "
                "observation(s)."
            ),
            exact_relevance=exact_relevance,
            independent_group="threatfox",
        )
    ]


def virustotal_evidence(
    *,
    malicious: int,
    suspicious: int,
    harmless: int = 0,
) -> list[Evidence]:
    if malicious >= 5:
        return [
            Evidence(
                source="VirusTotal",
                family=EvidenceFamily.REPUTATION,
                direction=EvidenceDirection.MALICIOUS,
                strength=EvidenceStrength.STRONG,
                confidence=min(
                    0.99,
                    0.75
                    + malicious
                    * 0.02,
                ),
                signal="multiple_malicious_engines",
                reason=(
                    f"VirusTotal reports {malicious} "
                    "malicious detections."
                ),
                independent_group="virustotal",
            )
        ]

    if malicious >= 2:
        return [
            Evidence(
                source="VirusTotal",
                family=EvidenceFamily.REPUTATION,
                direction=EvidenceDirection.MALICIOUS,
                strength=EvidenceStrength.MODERATE,
                confidence=0.70,
                signal="limited_malicious_engines",
                reason=(
                    f"VirusTotal reports {malicious} "
                    "malicious detections."
                ),
                independent_group="virustotal",
            )
        ]

    if malicious == 1 or suspicious >= 1:
        return [
            Evidence(
                source="VirusTotal",
                family=EvidenceFamily.REPUTATION,
                direction=EvidenceDirection.MALICIOUS,
                strength=EvidenceStrength.WEAK,
                confidence=0.45,
                signal="isolated_detection",
                reason=(
                    "VirusTotal contains only isolated "
                    "malicious/suspicious detections."
                ),
                independent_group="virustotal",
            )
        ]

    return [
        Evidence(
            source="VirusTotal",
            family=EvidenceFamily.REPUTATION,
            direction=EvidenceDirection.NEUTRAL,
            strength=EvidenceStrength.WEAK,
            confidence=0.60,
            signal="no_malicious_detection",
            reason=(
                "VirusTotal contains no malicious detection."
            ),
            independent_group="virustotal",
        )
    ]


def domain_age_evidence(
    *,
    age_days: int | None,
) -> list[Evidence]:
    if age_days is None:
        return []

    if age_days <= 7:
        return [
            Evidence(
                source="RDAP",
                family=EvidenceFamily.INFRASTRUCTURE,
                direction=EvidenceDirection.MALICIOUS,
                strength=EvidenceStrength.MODERATE,
                confidence=0.75,
                signal="very_new_domain",
                reason=(
                    f"The domain is approximately "
                    f"{age_days} day(s) old."
                ),
                independent_group="rdap",
            )
        ]

    if age_days <= 30:
        return [
            Evidence(
                source="RDAP",
                family=EvidenceFamily.INFRASTRUCTURE,
                direction=EvidenceDirection.MALICIOUS,
                strength=EvidenceStrength.WEAK,
                confidence=0.65,
                signal="new_domain",
                reason=(
                    f"The domain is approximately "
                    f"{age_days} days old."
                ),
                independent_group="rdap",
            )
        ]

    if age_days >= 3650:
        return [
            Evidence(
                source="RDAP",
                family=EvidenceFamily.INFRASTRUCTURE,
                direction=EvidenceDirection.BENIGN,
                strength=EvidenceStrength.WEAK,
                confidence=0.80,
                signal="long_lived_domain",
                reason=(
                    "The domain has existed for many years."
                ),
                independent_group="rdap",
            )
        ]

    return []


def impersonation_evidence(
    *,
    detected: bool,
    similarity: float = 0.0,
    claimed_brand: str | None = None,
) -> list[Evidence]:
    if not detected:
        return []

    strength = (
        EvidenceStrength.STRONG
        if similarity >= 0.90
        else EvidenceStrength.MODERATE
    )

    return [
        Evidence(
            source="brand_impersonation",
            family=EvidenceFamily.BEHAVIOR,
            direction=EvidenceDirection.MALICIOUS,
            strength=strength,
            confidence=max(
                0.65,
                min(
                    similarity,
                    0.99,
                ),
            ),
            signal="brand_impersonation",
            reason=(
                "The domain appears to imitate"
                + (
                    f" {claimed_brand}."
                    if claimed_brand
                    else " a known organization."
                )
            ),
            independent_group="brand_impersonation",
        )
    ]


def urlhaus_exact_evidence(
    *,
    matched: bool,
    match_type: str = "none",
) -> list[Evidence]:
    if (
        matched
        and match_type
        == "exact_url"
    ):
        return [
            Evidence(
                source="URLhaus",
                family=EvidenceFamily.REPUTATION,
                direction=EvidenceDirection.MALICIOUS,
                strength=EvidenceStrength.STRONG,
                confidence=0.98,
                signal="exact_urlhaus_url_match",
                reason=(
                    "The exact URL appears in the "
                    "URLhaus malicious URL feed."
                ),
                exact_relevance=True,
                independent_group="urlhaus",
            )
        ]

    return [
        Evidence(
            source="URLhaus",
            family=EvidenceFamily.REPUTATION,
            direction=EvidenceDirection.NEUTRAL,
            strength=EvidenceStrength.WEAK,
            confidence=0.50,
            signal="no_exact_urlhaus_match",
            reason=(
                "No exact URLhaus URL match was found."
            ),
            exact_relevance=True,
            independent_group="urlhaus",
        )
    ]
