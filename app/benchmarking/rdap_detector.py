from __future__ import annotations

from typing import Any

from app.benchmarking.offline_detector import (
    analyze_offline,
)
from app.domain_structure.fusion_adapter import (
    structure_evidence,
)
from app.evidence_fusion.adapters import (
    identity_evidence,
    urlhaus_exact_evidence,
)
from app.evidence_fusion.engine import (
    fuse_evidence,
)
from app.global_entity_registry.source_agreement import (
    evaluate_domain_identity,
)
from app.benchmarking.urlhaus_index import (
    exact_lookup,
)
from app.rdap_intelligence.fusion_adapter import (
    rdap_evidence,
)


def analyze_with_rdap(
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

    evidence += structure_evidence(
        value
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

    rdap_items, rdap_result = (
        rdap_evidence(
            value
        )
    )

    evidence += rdap_items

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
        "rdap": rdap_result,
        "urlhaus": urlhaus,
        "safeguards": (
            fusion.safeguards_triggered
        ),
        "contributions": (
            fusion.contributions
        ),
    }
