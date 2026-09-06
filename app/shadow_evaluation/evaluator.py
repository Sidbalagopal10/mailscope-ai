from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.domain_intelligence.enriched_profile import (
    analyze_enriched_domain_profile,
)
from app.shadow_evaluation.domain_bridge import (
    build_shadow_evidence,
)


OUTPUT = Path(
    "data/shadow_evaluation/"
    "latest_shadow_report.json"
)


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def analyze_shadow(
    value: str,
    *,
    force_refresh: bool = False,
) -> dict[str, Any]:
    old = analyze_enriched_domain_profile(
        value,
        force_refresh=force_refresh,
        include_ct_subdomains=False,
        enable_virustotal=True,
    )

    shadow = build_shadow_evidence(
        url=value,
        old_result=old,
    )

    fusion = shadow[
        "fusion"
    ]

    identity = shadow[
        "identity"
    ]

    old_score = old.get(
        "final_score"
    )

    try:
        old_score = float(
            old_score
        )
    except (
        TypeError,
        ValueError,
    ):
        old_score = None

    return {
        "input": value,
        "analyzed_at": utc_now(),

        "old": {
            "score": old_score,
            "risk_level": old.get(
                "risk_level"
            ),
            "classification": old.get(
                "classification"
            ),
            "is_phishing": old.get(
                "is_phishing"
            ),
        },

        "new": {
            "score": fusion.risk_score,
            "risk_level": fusion.risk_level,
            "verdict": fusion.verdict,
            "confidence": fusion.confidence,
            "identity_state": (
                fusion.identity_state
            ),
            "corroborating_malicious_families": (
                fusion
                .corroborating_malicious_families
            ),
            "safeguards": (
                fusion
                .safeguards_triggered
            ),
            "contributions": (
                fusion.contributions
            ),
        },

        "identity": {
            "state": identity.get(
                "identity_state"
            ),
            "official_domain": identity.get(
                "official_domain"
            ),
            "confidence": identity.get(
                "confidence"
            ),
            "entity": identity.get(
                "entity"
            ),
            "sources": identity.get(
                "independent_domain_sources"
            ),
            "reason": identity.get(
                "reason"
            ),
        },

        "normalized_inputs": shadow[
            "normalized_inputs"
        ],
    }


def run_shadow_suite(
    values: list[str],
    *,
    force_refresh: bool = False,
) -> dict[str, Any]:
    rows = []

    for value in values:
        try:
            rows.append(
                analyze_shadow(
                    value,
                    force_refresh=force_refresh,
                )
            )

        except Exception as error:
            rows.append(
                {
                    "input": value,
                    "error": (
                        f"{type(error).__name__}: "
                        f"{error}"
                    ),
                }
            )

    report = {
        "generated_at": utc_now(),
        "count": len(
            rows
        ),
        "results": rows,
    }

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
            default=str,
        ),
        encoding="utf-8",
    )

    return report
