from __future__ import annotations

from typing import Any

from app.evidence_fusion.adapters import (
    domain_age_evidence,
    identity_evidence,
    impersonation_evidence,
    threatfox_evidence,
    virustotal_evidence,
)
from app.evidence_fusion.engine import (
    fuse_evidence,
)
from app.global_entity_registry.source_agreement import (
    evaluate_domain_identity,
)


def mapping(
    value: Any,
) -> dict[str, Any]:
    return (
        value
        if isinstance(value, dict)
        else {}
    )


def integer(
    value: Any,
    default: int = 0,
) -> int:
    try:
        return int(
            value or default
        )
    except (
        TypeError,
        ValueError,
    ):
        return default


def floating(
    value: Any,
    default: float = 0.0,
) -> float:
    try:
        return float(
            value or default
        )
    except (
        TypeError,
        ValueError,
    ):
        return default


def threatfox_from_old_result(
    result: dict[str, Any],
) -> dict[str, Any]:
    threatfox = mapping(
        result.get(
            "threatfox_intelligence"
        )
    )

    domain_lookup = mapping(
        threatfox.get(
            "domain_lookup"
        )
    )

    observation = mapping(
        domain_lookup.get(
            "observation"
        )
    )

    matched = bool(
        threatfox.get(
            "matched",
            False,
        )
        or domain_lookup.get(
            "matched",
            False,
        )
    )

    relevance = threatfox.get(
        "relevance_validated"
    )

    if relevance is None:
        relevance = threatfox.get(
            "relevant_exact_match"
        )

    exact_relevance = bool(
        relevance
    )

    confidence = floating(
        observation.get(
            "maximum_confidence"
        ),
        default=0.0,
    )

    if confidence > 1:
        confidence /= 100.0

    count = integer(
        observation.get(
            "match_count"
        )
        or observation.get(
            "matches"
        )
        or threatfox.get(
            "match_count"
        ),
        default=0,
    )

    return {
        "matched": matched,
        "exact_relevance": exact_relevance,
        "confidence": max(
            0.0,
            min(
                confidence,
                1.0,
            ),
        ),
        "ioc_count": count,
    }


def virustotal_from_old_result(
    result: dict[str, Any],
) -> dict[str, int]:
    vt = mapping(
        result.get(
            "virustotal_intelligence"
        )
    )

    return {
        "malicious": integer(
            vt.get(
                "maximum_malicious"
            )
            or vt.get(
                "malicious"
            ),
        ),
        "suspicious": integer(
            vt.get(
                "maximum_suspicious"
            )
            or vt.get(
                "suspicious"
            ),
        ),
        "harmless": integer(
            vt.get(
                "maximum_harmless"
            )
            or vt.get(
                "harmless"
            ),
        ),
    }


def domain_age_from_old_result(
    result: dict[str, Any],
) -> int | None:
    rdap = mapping(
        result.get(
            "rdap_intelligence"
        )
    )

    raw = (
        rdap.get(
            "domain_age_days"
        )
        or rdap.get(
            "age_days"
        )
    )

    if raw is None:
        return None

    try:
        return int(
            raw
        )
    except (
        TypeError,
        ValueError,
    ):
        return None


def impersonation_from_old_result(
    result: dict[str, Any],
) -> dict[str, Any]:
    brand = mapping(
        result.get(
            "global_brand_intelligence"
        )
    )

    detected = bool(
        brand.get(
            "impersonation_detected",
            False,
        )
    )

    similarity = floating(
        brand.get(
            "similarity"
        )
        or brand.get(
            "similarity_score"
        ),
        default=0.0,
    )

    if similarity > 1:
        similarity /= 100.0

    return {
        "detected": detected,
        "similarity": max(
            0.0,
            min(
                similarity,
                1.0,
            ),
        ),
        "claimed_brand": (
            brand.get(
                "matched_brand"
            )
            or brand.get(
                "brand"
            )
        ),
    }


def build_shadow_evidence(
    *,
    url: str,
    old_result: dict[str, Any],
):
    identity = evaluate_domain_identity(
        url
    )

    evidence = []

    evidence += identity_evidence(
        identity
    )

    tf = threatfox_from_old_result(
        old_result
    )

    evidence += threatfox_evidence(
        matched=tf[
            "matched"
        ],
        exact_relevance=tf[
            "exact_relevance"
        ],
        confidence=tf[
            "confidence"
        ],
        ioc_count=tf[
            "ioc_count"
        ],
    )

    vt = virustotal_from_old_result(
        old_result
    )

    evidence += virustotal_evidence(
        malicious=vt[
            "malicious"
        ],
        suspicious=vt[
            "suspicious"
        ],
        harmless=vt[
            "harmless"
        ],
    )

    age = domain_age_from_old_result(
        old_result
    )

    evidence += domain_age_evidence(
        age_days=age
    )

    impersonation = impersonation_from_old_result(
        old_result
    )

    evidence += impersonation_evidence(
        detected=impersonation[
            "detected"
        ],
        similarity=impersonation[
            "similarity"
        ],
        claimed_brand=impersonation[
            "claimed_brand"
        ],
    )

    fusion = fuse_evidence(
        evidence,
        identity_state=identity.get(
            "identity_state"
        ),
    )

    return {
        "identity": identity,
        "fusion": fusion,
        "normalized_inputs": {
            "threatfox": tf,
            "virustotal": vt,
            "domain_age_days": age,
            "impersonation": impersonation,
        },
    }
