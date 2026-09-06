from __future__ import annotations

from typing import Any

from app.domain_intelligence.safe_unified_profile import (
    analyze_unified_domain_profile,
)
from app.threat_intelligence.virustotal_client import (
    lookup_url_and_domain,
)
from app.threat_intelligence.virustotal_risk import (
    combine_virustotal_evidence,
)


def clamp(
    value: float,
    minimum: float = 0.0,
    maximum: float = 100.0,
) -> float:
    return max(
        minimum,
        min(
            value,
            maximum,
        ),
    )


def risk_level_for_score(
    score: float,
) -> str:
    if score >= 80:
        return "critical"

    if score >= 60:
        return "high"

    if score >= 35:
        return "moderate"

    return "low"


def classification_for_score(
    score: float,
) -> str:
    if score >= 80:
        return "likely_phishing"

    if score >= 60:
        return "high_risk"

    if score >= 35:
        return "needs_review"

    return "likely_legitimate"


def safe_virustotal_lookup(
    url: str,
    *,
    force_refresh: bool = False,
) -> dict[str, Any]:
    try:
        lookup = lookup_url_and_domain(
            url,
            force=force_refresh,
        )

        evidence = combine_virustotal_evidence(
            lookup
        )

        return {
            "available": True,
            "lookup": lookup,
            "evidence": evidence,
            "error": None,
        }

    except Exception as error:
        # External-service failures must remain neutral.
        return {
            "available": False,
            "lookup": None,
            "evidence": {
                "matched": False,
                "risk_adjustment": 0.0,
                "confidence_adjustment": 0.0,
                "url_evidence": {},
                "domain_evidence": {},
            },
            "error": str(
                error
            ),
        }


def analyze_enriched_domain_profile(
    value: str,
    *,
    force_refresh: bool = False,
    include_ct_subdomains: bool = False,
    enable_virustotal: bool = True,
) -> dict[str, Any]:
    """
    Combine the existing Unified Domain Profile with bounded
    VirusTotal evidence.

    Important safety rules:
    - An API outage adds no risk.
    - One malicious vendor cannot force a phishing verdict alone.
    - Strong multi-engine detection can raise the score substantially.
    - Existing high-confidence phishing evidence is never reduced.
    """
    base = analyze_unified_domain_profile(
        value,
        force_refresh=force_refresh,
        include_ct_subdomains=(
            include_ct_subdomains
        ),
    )

    base_score = float(
        base.get(
            "final_score",
            0.0,
        )
        or 0.0
    )

    base_reasons = list(
        base.get(
            "reasons",
            [],
        )
        or []
    )

    if enable_virustotal:
        vt = safe_virustotal_lookup(
            value,
            force_refresh=force_refresh,
        )

    else:
        vt = {
            "available": False,
            "lookup": None,
            "evidence": {
                "matched": False,
                "risk_adjustment": 0.0,
                "confidence_adjustment": 0.0,
                "url_evidence": {},
                "domain_evidence": {},
            },
            "error": (
                "VirusTotal was disabled for this analysis."
            ),
        }

    evidence = vt.get(
        "evidence",
        {},
    )

    raw_adjustment = float(
        evidence.get(
            "risk_adjustment",
            0.0,
        )
        or 0.0
    )

    url_evidence = evidence.get(
        "url_evidence",
        {},
    )

    domain_evidence = evidence.get(
        "domain_evidence",
        {},
    )

    maximum_malicious = max(
        int(
            url_evidence.get(
                "malicious",
                0,
            )
            or 0
        ),
        int(
            domain_evidence.get(
                "malicious",
                0,
            )
            or 0
        ),
    )

    maximum_suspicious = max(
        int(
            url_evidence.get(
                "suspicious",
                0,
            )
            or 0
        ),
        int(
            domain_evidence.get(
                "suspicious",
                0,
            )
            or 0
        ),
    )

    # Prevent one isolated vendor from dominating the verdict.
    if maximum_malicious <= 1:
        applied_adjustment = min(
            raw_adjustment,
            16.0,
        )

    else:
        applied_adjustment = raw_adjustment

    official_domain_match = bool(
        (
            base.get(
                "global_brand_intelligence",
                {},
            )
            or {}
        ).get(
            "official_domain_match",
            False,
        )
    )

    brand_impersonation = bool(
        (
            base.get(
                "global_brand_intelligence",
                {},
            )
            or {}
        ).get(
            "impersonation_detected",
            False,
        )
    )

    threatfox_match = bool(
        (
            base.get(
                "threatfox_intelligence",
                {},
            )
            or {}
        ).get(
            "matched",
            False,
        )
    )

    # Official domains require corroboration before weak VT detections
    # can materially affect the result.
    if (
        official_domain_match
        and maximum_malicious <= 1
        and not brand_impersonation
        and not threatfox_match
    ):
        applied_adjustment = 0.0

    final_score = clamp(
        base_score
        + applied_adjustment
    )

    # Strong multi-engine detection creates a minimum score floor.
    if maximum_malicious >= 10:
        final_score = max(
            final_score,
            90.0,
        )

    elif maximum_malicious >= 5:
        final_score = max(
            final_score,
            82.0,
        )

    elif maximum_malicious >= 2:
        final_score = max(
            final_score,
            70.0,
        )

    reasons = list(
        base_reasons
    )

    if not vt.get(
        "available"
    ):
        reasons.append(
            "VirusTotal Intelligence: unavailable; no risk "
            "was added from the failed lookup."
        )

    elif maximum_malicious >= 2:
        reasons.append(
            "VirusTotal Intelligence: multiple security "
            f"engines reported the URL or domain as malicious "
            f"(maximum malicious detections: "
            f"{maximum_malicious})."
        )

    elif maximum_malicious == 1:
        reasons.append(
            "VirusTotal Intelligence: one engine reported a "
            "malicious result. The adjustment was bounded because "
            "isolated detections can be false positives."
        )

    elif maximum_suspicious > 0:
        reasons.append(
            "VirusTotal Intelligence: one or more engines "
            "reported suspicious activity."
        )

    else:
        reasons.append(
            "VirusTotal Intelligence: no malicious or suspicious "
            "detections were found. This does not prove safety."
        )

    if (
        official_domain_match
        and maximum_malicious <= 1
        and applied_adjustment == 0
    ):
        reasons.append(
            "VirusTotal Intelligence: weak isolated reputation "
            "evidence did not override exact official-domain identity."
        )

    final_score = round(
        final_score,
        2,
    )

    risk_level = risk_level_for_score(
        final_score
    )

    classification = (
        classification_for_score(
            final_score
        )
    )

    result = {
        **base,
        "base_unified_score": round(
            base_score,
            2,
        ),
        "final_score": final_score,
        "risk_score": final_score,
        "risk_level": risk_level,
        "classification": classification,
        "is_phishing": bool(
            final_score >= 60
        ),
        "reasons": reasons,
        "virustotal_intelligence": {
            "available": vt.get(
                "available",
                False,
            ),
            "error": vt.get(
                "error"
            ),
            "matched": bool(
                evidence.get(
                    "matched",
                    False,
                )
            ),
            "maximum_malicious": (
                maximum_malicious
            ),
            "maximum_suspicious": (
                maximum_suspicious
            ),
            "raw_risk_adjustment": (
                raw_adjustment
            ),
            "applied_score_adjustment": (
                applied_adjustment
            ),
            "lookup": vt.get(
                "lookup"
            ),
            "evidence": evidence,
        },
    }

    evidence_summary = dict(
        result.get(
            "evidence_summary",
            {},
        )
        or {}
    )

    evidence_summary.update(
        {
            "virustotal_available": (
                vt.get(
                    "available",
                    False,
                )
            ),
            "virustotal_matched": bool(
                evidence.get(
                    "matched",
                    False,
                )
            ),
            "virustotal_maximum_malicious": (
                maximum_malicious
            ),
            "virustotal_maximum_suspicious": (
                maximum_suspicious
            ),
            "virustotal_applied_adjustment": (
                applied_adjustment
            ),
        }
    )

    result[
        "evidence_summary"
    ] = evidence_summary

    limitations = list(
        result.get(
            "important_limitations",
            [],
        )
        or []
    )

    limitations.extend(
        [
            (
                "VirusTotal aggregates third-party verdicts; "
                "individual engines can produce false positives."
            ),
            (
                "A clean VirusTotal result does not establish "
                "that an indicator is safe."
            ),
            (
                "VirusTotal public API access is selective and "
                "quota limited."
            ),
        ]
    )

    result[
        "important_limitations"
    ] = list(
        dict.fromkeys(
            limitations
        )
    )

    return result
