from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.domain_intelligence.enriched_profile import (
    analyze_enriched_domain_profile,
)
from app.domain_intelligence.unified_profile import (
    analyze_unified_domain_profile,
)


DEFAULT_DOMAINS = [
    "google.com",
    "microsoft.com",
    "apple.com",
    "nvidia.com",
    "github.com",
    "gwu.edu",
]

REPORT_DIRECTORY = Path(
    "data/diagnostics"
)

SCORE_TERMS = {
    "score",
    "risk",
    "adjustment",
    "delta",
    "penalty",
    "bonus",
    "weight",
    "confidence",
    "probability",
}

DECISION_TERMS = {
    "matched",
    "detected",
    "official",
    "verified",
    "trusted",
    "phishing",
    "malicious",
    "suspicious",
    "impersonation",
    "available",
    "found",
}


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def is_score_key(
    key: str,
) -> bool:
    lowered = str(
        key
    ).lower()

    return any(
        term in lowered
        for term in SCORE_TERMS
    )


def is_decision_key(
    key: str,
) -> bool:
    lowered = str(
        key
    ).lower()

    return any(
        term in lowered
        for term in DECISION_TERMS
    )


def flatten_relevant_values(
    value: Any,
    *,
    path: str = "root",
) -> list[dict[str, Any]]:
    """
    Recursively collect score-like numeric values and
    security-relevant booleans without assuming a fixed schema.
    """
    findings: list[
        dict[str, Any]
    ] = []

    if isinstance(
        value,
        dict,
    ):
        for key, child in value.items():
            child_path = (
                f"{path}.{key}"
            )

            if (
                isinstance(
                    child,
                    (
                        int,
                        float,
                    ),
                )
                and not isinstance(
                    child,
                    bool,
                )
                and is_score_key(
                    key
                )
            ):
                findings.append(
                    {
                        "path": child_path,
                        "key": key,
                        "value": child,
                        "kind": "numeric_signal",
                    }
                )

            elif (
                isinstance(
                    child,
                    bool,
                )
                and is_decision_key(
                    key
                )
            ):
                findings.append(
                    {
                        "path": child_path,
                        "key": key,
                        "value": child,
                        "kind": "decision_flag",
                    }
                )

            findings.extend(
                flatten_relevant_values(
                    child,
                    path=child_path,
                )
            )

    elif isinstance(
        value,
        list,
    ):
        for index, child in enumerate(
            value
        ):
            findings.extend(
                flatten_relevant_values(
                    child,
                    path=(
                        f"{path}[{index}]"
                    ),
                )
            )

    return findings


def safe_mapping(
    value: Any,
) -> dict[str, Any]:
    return (
        value
        if isinstance(
            value,
            dict,
        )
        else {}
    )


def extract_module_summary(
    result: dict[str, Any],
) -> dict[str, Any]:
    brand = safe_mapping(
        result.get(
            "global_brand_intelligence"
        )
    )

    organization = safe_mapping(
        result.get(
            "organization_intelligence"
        )
    )

    threatfox = safe_mapping(
        result.get(
            "threatfox_intelligence"
        )
    )

    virustotal = safe_mapping(
        result.get(
            "virustotal_intelligence"
        )
    )

    rdap = safe_mapping(
        result.get(
            "rdap_intelligence"
        )
    )

    dns = safe_mapping(
        result.get(
            "dns_intelligence"
        )
    )

    certificate = safe_mapping(
        result.get(
            "certificate_transparency"
        )
    )

    ip_asn = safe_mapping(
        result.get(
            "ip_asn_intelligence"
        )
    )

    return {
        "top_level": {
            "base_score": result.get(
                "base_unified_score"
            ),
            "final_score": result.get(
                "final_score"
            ),
            "risk_score": result.get(
                "risk_score"
            ),
            "risk_level": result.get(
                "risk_level"
            ),
            "classification": result.get(
                "classification"
            ),
            "is_phishing": result.get(
                "is_phishing"
            ),
        },
        "brand": {
            "official_domain_match": (
                brand.get(
                    "official_domain_match"
                )
            ),
            "impersonation_detected": (
                brand.get(
                    "impersonation_detected"
                )
            ),
            "matched_brand": brand.get(
                "matched_brand"
            ),
            "risk_adjustment": brand.get(
                "risk_adjustment"
            ),
        },
        "organization": {
            "known_domain": (
                organization.get(
                    "known_domain"
                )
            ),
            "verified": organization.get(
                "verified"
            ),
            "organization_name": (
                organization.get(
                    "organization_name"
                )
                or organization.get(
                    "name"
                )
            ),
            "risk_adjustment": (
                organization.get(
                    "risk_adjustment"
                )
            ),
        },
        "threatfox": {
            "matched": threatfox.get(
                "matched"
            ),
            "risk_adjustment": (
                threatfox.get(
                    "risk_adjustment"
                )
            ),
            "error": threatfox.get(
                "error"
            ),
        },
        "virustotal": {
            "available": virustotal.get(
                "available"
            ),
            "matched": virustotal.get(
                "matched"
            ),
            "maximum_malicious": (
                virustotal.get(
                    "maximum_malicious"
                )
            ),
            "maximum_suspicious": (
                virustotal.get(
                    "maximum_suspicious"
                )
            ),
            "raw_risk_adjustment": (
                virustotal.get(
                    "raw_risk_adjustment"
                )
            ),
            "applied_score_adjustment": (
                virustotal.get(
                    "applied_score_adjustment"
                )
            ),
            "error": virustotal.get(
                "error"
            ),
        },
        "rdap": {
            "risk_adjustment": rdap.get(
                "risk_adjustment"
            ),
            "domain_age_days": (
                rdap.get(
                    "domain_age_days"
                )
            ),
            "available": rdap.get(
                "available"
            ),
        },
        "dns": {
            "risk_adjustment": dns.get(
                "risk_adjustment"
            ),
            "available": dns.get(
                "available"
            ),
        },
        "certificate_transparency": {
            "risk_adjustment": (
                certificate.get(
                    "risk_adjustment"
                )
            ),
            "available": certificate.get(
                "available"
            ),
        },
        "ip_asn": {
            "risk_adjustment": ip_asn.get(
                "risk_adjustment"
            ),
            "available": ip_asn.get(
                "available"
            ),
        },
        "evidence_summary": safe_mapping(
            result.get(
                "evidence_summary"
            )
        ),
        "reasons": list(
            result.get(
                "reasons",
                [],
            )
            or []
        ),
        "unavailable_sources": list(
            result.get(
                "unavailable_sources",
                [],
            )
            or []
        ),
    }


def analyze_domain_trace(
    domain: str,
    *,
    include_enriched: bool = True,
    force_refresh: bool = False,
) -> dict[str, Any]:
    value = str(
        domain
    ).strip()

    if not value:
        raise ValueError(
            "A domain is required."
        )

    if not value.startswith(
        (
            "http://",
            "https://",
        )
    ):
        value = (
            f"https://{value}/"
        )

    base_error = None
    enriched_error = None

    try:
        base_result = (
            analyze_unified_domain_profile(
                value,
                force_refresh=force_refresh,
                include_ct_subdomains=False,
            )
        )

    except Exception as error:
        base_result = {}
        base_error = str(
            error
        )

    enriched_result: dict[
        str,
        Any
    ] = {}

    if include_enriched:
        try:
            enriched_result = (
                analyze_enriched_domain_profile(
                    value,
                    force_refresh=force_refresh,
                    include_ct_subdomains=False,
                    enable_virustotal=True,
                )
            )

        except Exception as error:
            enriched_error = str(
                error
            )

    base_score = base_result.get(
        "final_score"
    )

    enriched_score = enriched_result.get(
        "final_score"
    )

    try:
        wrapper_delta = round(
            float(
                enriched_score
            )
            - float(
                base_score
            ),
            2,
        )

    except (
        TypeError,
        ValueError,
    ):
        wrapper_delta = None

    return {
        "input": domain,
        "normalized_input": value,
        "analyzed_at": utc_now(),
        "force_refresh": force_refresh,
        "base_error": base_error,
        "enriched_error": (
            enriched_error
        ),
        "comparison": {
            "base_final_score": (
                base_score
            ),
            "enriched_final_score": (
                enriched_score
            ),
            "enriched_wrapper_delta": (
                wrapper_delta
            ),
            "base_classification": (
                base_result.get(
                    "classification"
                )
            ),
            "enriched_classification": (
                enriched_result.get(
                    "classification"
                )
            ),
        },
        "base_summary": (
            extract_module_summary(
                base_result
            )
            if base_result
            else {}
        ),
        "enriched_summary": (
            extract_module_summary(
                enriched_result
            )
            if enriched_result
            else {}
        ),
        "base_relevant_values": (
            flatten_relevant_values(
                base_result,
                path="base",
            )
            if base_result
            else []
        ),
        "enriched_relevant_values": (
            flatten_relevant_values(
                enriched_result,
                path="enriched",
            )
            if enriched_result
            else []
        ),
        "base_raw_result": base_result,
        "enriched_raw_result": (
            enriched_result
        ),
    }


def run_domain_audit(
    domains: list[str] | None = None,
    *,
    force_refresh: bool = False,
) -> dict[str, Any]:
    selected_domains = (
        domains
        or list(
            DEFAULT_DOMAINS
        )
    )

    traces = [
        analyze_domain_trace(
            domain,
            force_refresh=force_refresh,
        )
        for domain in selected_domains
    ]

    report = {
        "report_version": "1.0.0",
        "generated_at": utc_now(),
        "force_refresh": force_refresh,
        "domain_count": len(
            traces
        ),
        "domains": traces,
    }

    REPORT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    output = (
        REPORT_DIRECTORY
        / "latest_domain_score_trace.json"
    )

    output.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
            default=str,
        ),
        encoding="utf-8",
    )

    return report
