from __future__ import annotations

from typing import Any

from app.benchmarking.offline_detector import (
    lexical_evidence,
    simple_brand_evidence,
)
from app.benchmarking.urlhaus_index import (
    exact_lookup,
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
from app.hosting_intelligence.corroboration import (
    shared_host_corroboration,
)
from app.hosting_intelligence.fusion_adapter import (
    hosting_evidence,
)


def analyze_with_hosting(
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

    # -------------------------------------------------
    # SAME BASELINE AS PHASE 14
    # -------------------------------------------------

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

    # -------------------------------------------------
    # NEW PHASE 16 HOSTING INTELLIGENCE
    # -------------------------------------------------

    hosting_items, hosting = (
        hosting_evidence(
            value
        )
    )

    evidence += hosting_items

    evidence += shared_host_corroboration(
        value=value,
        hosting=hosting,
        identity_state=identity_state,
    )

    # -------------------------------------------------
    # EXISTING URLHAUS EXACT INTELLIGENCE
    # -------------------------------------------------

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
        "risk_score": (
            fusion.risk_score
        ),
        "risk_level": (
            fusion.risk_level
        ),
        "verdict": (
            fusion.verdict
        ),
        "confidence": (
            fusion.confidence
        ),
        "identity_state": (
            identity_state
        ),
        "hosting": hosting,
        "urlhaus": urlhaus,
        "safeguards": (
            fusion.safeguards_triggered
        ),
        "contributions": (
            fusion.contributions
        ),
    }
