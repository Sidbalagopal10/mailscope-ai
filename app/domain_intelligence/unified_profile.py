from __future__ import annotations

from typing import Any

from app.brand_intelligence.global_brand_index import (
    analyze_brand_impersonation,
)
from urllib.parse import urlparse

from app.detection.hybrid_detector import (
    analyze_url_hybrid,
    clamp,
    determine_risk_level,
)
from app.domain_intelligence.certificate_transparency import (
    lookup_domain as lookup_ct,
)
from app.domain_intelligence.ct_risk import (
    certificate_transparency_evidence,
)
from app.domain_intelligence.rdap_client import (
    lookup_domain as lookup_rdap,
)
from app.domain_intelligence.risk import (
    rdap_risk_evidence,
)
from app.dns_intelligence.dns_lookup import (
    lookup_domain as lookup_dns,
)
from app.dns_intelligence.dns_risk import (
    dns_risk_evidence,
)
from app.network_intelligence.ip_asn_intelligence import (
    lookup_hostname as lookup_ip_asn,
)
from app.network_intelligence.risk import (
    ip_asn_risk_evidence,
)

from app.threat_intelligence.threatfox_client import (
    lookup_indicator as lookup_threatfox,
)
from app.threat_intelligence.threatfox_risk import (
    threatfox_risk_evidence,
)

from app.organization_intelligence.scoring import (
    identity_score_adjustment,
)


def normalize_url(
    value: str,
) -> str:
    cleaned = str(
        value or ""
    ).strip()

    if not cleaned:
        raise ValueError(
            "A URL or domain is required."
        )

    if not cleaned.startswith(
        (
            "http://",
            "https://",
        )
    ):
        cleaned = (
            "https://"
            + cleaned
        )

    parsed = urlparse(
        cleaned
    )

    if not parsed.hostname:
        raise ValueError(
            "Enter a valid domain or URL."
        )

    return cleaned


def extract_hostname(
    url: str,
) -> str:
    parsed = urlparse(
        url
    )

    hostname = str(
        parsed.hostname or ""
    ).lower().rstrip(".")

    if hostname.startswith(
        "www."
    ):
        hostname = hostname[4:]

    if not hostname:
        raise ValueError(
            "The URL does not contain a hostname."
        )

    return hostname


def safe_lookup(
    function,
    *args,
    **kwargs,
) -> dict[str, Any]:
    try:
        result = function(
            *args,
            **kwargs,
        )

        return {
            "available": True,
            "result": result,
            "error": None,
        }

    except Exception as error:
        return {
            "available": False,
            "result": None,
            "error": str(
                error
            ),
        }


def classification_for_score(
    score: float,
) -> str:
    if score >= 70:
        return "likely_phishing"

    if score >= 55:
        return "high_risk"

    if score >= 35:
        return "suspicious"

    if score >= 20:
        return "needs_review"

    return "likely_legitimate"


def recommendation_for_score(
    score: float,
) -> str:
    if score >= 70:
        return (
            "Do not open this URL. Verify the organization "
            "through a separately obtained official source."
        )

    if score >= 55:
        return (
            "Treat this URL as high risk. Do not enter "
            "credentials or payment information."
        )

    if score >= 35:
        return (
            "Verify the sender and destination before "
            "opening the URL."
        )

    if score >= 20:
        return (
            "The available evidence is inconclusive. "
            "Verify the organization independently."
        )

    return (
        "No strong phishing evidence was detected. "
        "Continue to use normal caution."
    )


def confidence_level(
    confidence: float,
) -> str:
    if confidence >= 80:
        return "high"

    if confidence >= 60:
        return "medium"

    return "low"


def _analyze_unified_domain_profile_legacy(
    value: str,
    *,
    force_refresh: bool = False,
    include_ct_subdomains: bool = False,
) -> dict[str, Any]:
    """
    Produce one explainable profile from local detection and
    external registration, certificate, DNS and organization
    evidence.

    No single source can independently declare a URL safe.
    """
    url = normalize_url(
        value
    )

    hostname = extract_hostname(
        url
    )

    hybrid_lookup = safe_lookup(
        analyze_url_hybrid,
        url,
    )

    if not hybrid_lookup[
        "available"
    ]:
        raise RuntimeError(
            "The hybrid URL detector failed: "
            f"{hybrid_lookup['error']}"
        )

    hybrid = hybrid_lookup[
        "result"
    ]

    organization_lookup = safe_lookup(
        identity_score_adjustment,
        hostname,
    )

    global_brand_lookup = safe_lookup(
        analyze_brand_impersonation,
        hostname,
    )

    rdap_lookup = safe_lookup(
        lookup_rdap,
        hostname,
        force=force_refresh,
    )

    ct_lookup = safe_lookup(
        lookup_ct,
        hostname,
        include_subdomains=(
            include_ct_subdomains
        ),
        force=force_refresh,
    )

    dns_lookup = safe_lookup(
        lookup_dns,
        hostname,
        force=force_refresh,
    )

    ip_asn_lookup = safe_lookup(
        lookup_ip_asn,
        hostname,
        force=force_refresh,
    )

    threatfox_url_lookup = safe_lookup(
        lookup_threatfox,
        url,
        force=force_refresh,
    )

    threatfox_domain_lookup = safe_lookup(
        lookup_threatfox,
        hostname,
        force=force_refresh,
    )

    organization = (
        organization_lookup[
            "result"
        ]
        if organization_lookup[
            "available"
        ]
        else {
            "matched": False,
            "identity_state": "UNKNOWN",
            "security_state": "NEUTRAL",
            "score_adjustment": 0.0,
            "identity_confidence": 0.0,
            "security_confidence": 0.0,
            "reasons": [],
            "record": None,
        }
    )

    global_brand = (
        global_brand_lookup[
            "result"
        ]
        if global_brand_lookup[
            "available"
        ]
        else {
            "hostname": hostname,
            "official_domain_match": False,
            "official_owner": None,
            "impersonation_detected": False,
            "strongest_finding": None,
            "findings": [],
            "risk_adjustment": 0.0,
            "important_limitations": [],
        }
    )

    rdap_observation = (
        rdap_lookup[
            "result"
        ]
        if rdap_lookup[
            "available"
        ]
        else None
    )

    ct_observation = (
        ct_lookup[
            "result"
        ]
        if ct_lookup[
            "available"
        ]
        else None
    )

    dns_observation = (
        dns_lookup[
            "result"
        ]
        if dns_lookup[
            "available"
        ]
        else None
    )

    ip_asn_observation = (
        ip_asn_lookup[
            "result"
        ]
        if ip_asn_lookup[
            "available"
        ]
        else None
    )

    threatfox_url_observation = (
        threatfox_url_lookup[
            "result"
        ]
        if threatfox_url_lookup[
            "available"
        ]
        else None
    )

    threatfox_domain_observation = (
        threatfox_domain_lookup[
            "result"
        ]
        if threatfox_domain_lookup[
            "available"
        ]
        else None
    )

    rdap_evidence = (
        rdap_risk_evidence(
            rdap_observation
        )
    )

    ct_evidence = (
        certificate_transparency_evidence(
            ct_observation
        )
    )

    dns_evidence = (
        dns_risk_evidence(
            dns_observation
        )
    )

    ip_asn_evidence = (
        ip_asn_risk_evidence(
            ip_asn_observation
        )
    )

    threatfox_url_evidence = (
        threatfox_risk_evidence(
            threatfox_url_observation
        )
    )

    threatfox_domain_evidence = (
        threatfox_risk_evidence(
            threatfox_domain_observation
        )
    )

    threatfox_matched = bool(
        threatfox_url_evidence.get(
            "matched",
            False,
        )
        or threatfox_domain_evidence.get(
            "matched",
            False,
        )
    )

    threatfox_adjustment = max(
        float(
            threatfox_url_evidence.get(
                "risk_adjustment",
                0.0,
            )
            or 0.0
        ),
        float(
            threatfox_domain_evidence.get(
                "risk_adjustment",
                0.0,
            )
            or 0.0
        ),
    )

    threatfox_confidence_adjustment = max(
        float(
            threatfox_url_evidence.get(
                "confidence_adjustment",
                0.0,
            )
            or 0.0
        ),
        float(
            threatfox_domain_evidence.get(
                "confidence_adjustment",
                0.0,
            )
            or 0.0
        ),
    )

    base_score = float(
        hybrid.get(
            "final_score",
            0.0,
        )
        or 0.0
    )

    corroboration = hybrid.get(
        "corroborating_evidence",
        {},
    )

    strong_signal_count = int(
        corroboration.get(
            "strong_signal_count",
            0,
        )
        or 0
    )

    weak_signal_count = int(
        corroboration.get(
            "weak_signal_count",
            0,
        )
        or 0
    )

    legacy_brand_intelligence = hybrid.get(
        "brand_intelligence",
        {},
    )

    legacy_brand_impersonation = bool(
        legacy_brand_intelligence.get(
            "impersonation_detected",
            False,
        )
    )

    global_brand_impersonation = bool(
        global_brand.get(
            "impersonation_detected",
            False,
        )
    )

    official_brand_domain = bool(
        global_brand.get(
            "official_domain_match",
            False,
        )
    )

    brand_impersonation = bool(
        legacy_brand_impersonation
        or global_brand_impersonation
    )

    organization_requested_adjustment = float(
        organization.get(
            "score_adjustment",
            0.0,
        )
        or 0.0
    )

    organization_applied_adjustment = 0.0
    organization_adjustment_blocked = False

    identity_state = organization.get(
        "identity_state",
        "UNKNOWN",
    )

    security_state = organization.get(
        "security_state",
        "NEUTRAL",
    )

    malicious_security_states = {
        "KNOWN_MALICIOUS",
        "COMPROMISED_LEGITIMATE",
        "SUSPICIOUS",
    }

    if (
        security_state
        in malicious_security_states
    ):
        organization_applied_adjustment = max(
            organization_requested_adjustment,
            0.0,
        )

    elif (
        organization.get(
            "matched",
            False,
        )
        and organization_requested_adjustment
        < 0
    ):
        contradictory_evidence = any(
            [
                strong_signal_count >= 1,
                brand_impersonation,
                base_score >= 70,
            ]
        )

        if contradictory_evidence:
            organization_adjustment_blocked = True

        else:
            organization_applied_adjustment = (
                organization_requested_adjustment
            )

    rdap_adjustment = float(
        rdap_evidence.get(
            "risk_adjustment",
            0.0,
        )
        or 0.0
    )

    ct_adjustment = float(
        ct_evidence.get(
            "risk_adjustment",
            0.0,
        )
        or 0.0
    )

    dns_adjustment = float(
        dns_evidence.get(
            "risk_adjustment",
            0.0,
        )
        or 0.0
    )

    ip_asn_adjustment = float(
        ip_asn_evidence.get(
            "risk_adjustment",
            0.0,
        )
        or 0.0
    )

    # Positive infrastructure history must not suppress
    # independent phishing evidence.
    positive_adjustment_blocked = bool(
        strong_signal_count >= 1
        or brand_impersonation
        or threatfox_matched
        or base_score >= 70
    )

    if positive_adjustment_blocked:
        rdap_adjustment = max(
            rdap_adjustment,
            0.0,
        )

        ct_adjustment = max(
            ct_adjustment,
            0.0,
        )

        dns_adjustment = max(
            dns_adjustment,
            0.0,
        )

        ip_asn_adjustment = max(
            ip_asn_adjustment,
            0.0,
        )

    global_brand_requested_adjustment = float(
        global_brand.get(
            "risk_adjustment",
            0.0,
        )
        or 0.0
    )

    global_brand_applied_adjustment = 0.0

    if global_brand_impersonation:
        strongest_finding = (
            global_brand.get(
                "strongest_finding"
            )
            or {}
        )

        finding_type = strongest_finding.get(
            "type"
        )

        similarity = float(
            strongest_finding.get(
                "similarity",
                0.0,
            )
            or 0.0
        )

        # Keep global brand evidence strong but bounded.
        if finding_type == "typosquatting":
            global_brand_applied_adjustment = min(
                max(
                    global_brand_requested_adjustment,
                    20.0,
                ),
                38.0,
            )

        elif finding_type == "brand_on_unofficial_domain":
            global_brand_applied_adjustment = min(
                max(
                    global_brand_requested_adjustment,
                    16.0,
                ),
                30.0,
            )

        else:
            global_brand_applied_adjustment = min(
                global_brand_requested_adjustment,
                28.0,
            )

        # Lower-confidence fuzzy matches remain bounded.
        if similarity < 0.88:
            global_brand_applied_adjustment = min(
                global_brand_applied_adjustment,
                22.0,
            )

    elif official_brand_domain:
        # Official ownership is identity evidence only.
        # It must not reduce URL risk by itself.
        global_brand_applied_adjustment = 0.0

    total_adjustment = (
        organization_applied_adjustment
        + rdap_adjustment
        + ct_adjustment
        + dns_adjustment
        + ip_asn_adjustment
        + global_brand_applied_adjustment
        + threatfox_adjustment
    )

    # Prevent intelligence enrichment from dominating the
    # detector in either direction.
    total_adjustment = max(
        -22.0,
        min(
            total_adjustment,
            30.0,
        ),
    )

    final_score = clamp(
        base_score
        + total_adjustment
    )

    # A verified established organization with no contradictory
    # phishing evidence may move below GUARDED, even when the
    # legacy ML classifier is overconfident.
    if (
        identity_state
        == "VERIFIED_ESTABLISHED"
        and security_state
        in {
            "CLEAN",
            "NEUTRAL",
        }
        and strong_signal_count == 0
        and not brand_impersonation
        and not organization_adjustment_blocked
    ):
        final_score = min(
            final_score,
            18.0,
        )

    if threatfox_matched:
        final_score = max(
            final_score,
            85.0,
        )

    final_score = round(
        final_score,
        2,
    )

    confidence = float(
        hybrid.get(
            "confidence_percentage",
            50.0,
        )
        or 50.0
    )

    confidence_adjustments = [
        float(
            rdap_evidence.get(
                "confidence_adjustment",
                0.0,
            )
            or 0.0
        ),
        float(
            ct_evidence.get(
                "confidence_adjustment",
                0.0,
            )
            or 0.0
        ),
        float(
            dns_evidence.get(
                "confidence_adjustment",
                0.0,
            )
            or 0.0
        ),
        float(
            ip_asn_evidence.get(
                "confidence_adjustment",
                0.0,
            )
            or 0.0
        ),
        threatfox_confidence_adjustment,
    ]

    if organization.get(
        "matched",
        False,
    ):
        identity_confidence = float(
            organization.get(
                "identity_confidence",
                0.0,
            )
            or 0.0
        )

        confidence = max(
            confidence,
            (
                confidence * 0.45
                + identity_confidence
                * 0.55
            ),
        )

    confidence += min(
        sum(
            confidence_adjustments
        ),
        12.0,
    )

    confidence = round(
        clamp(
            confidence,
            0,
            99,
        ),
        2,
    )

    risk_level = determine_risk_level(
        final_score
    )

    classification = classification_for_score(
        final_score
    )

    reasons = list(
        hybrid.get(
            "reasons",
            [],
        )
    )

    if threatfox_matched:
        matched_evidences = [
            evidence
            for evidence in (
                threatfox_url_evidence,
                threatfox_domain_evidence,
            )
            if evidence.get(
                "matched",
                False,
            )
        ]

        malware_families = sorted(
            {
                family
                for evidence in matched_evidences
                for family in evidence.get(
                    "malware_families",
                    [],
                )
            }
        )

        threat_types = sorted(
            {
                threat_type
                for evidence in matched_evidences
                for threat_type in evidence.get(
                    "threat_types",
                    [],
                )
            }
        )

        reasons.append(
            "ThreatFox Intelligence: The submitted URL or "
            "domain matched malware-associated IOC records."
        )

        if malware_families:
            reasons.append(
                "ThreatFox Intelligence: Malware families: "
                + ", ".join(
                    malware_families[:10]
                )
            )

        if threat_types:
            reasons.append(
                "ThreatFox Intelligence: Threat types: "
                + ", ".join(
                    threat_types[:10]
                )
            )

        reasons.append(
            "ThreatFox Intelligence: Positive infrastructure "
            "history was prevented from lowering the verdict."
        )


    if global_brand_impersonation:
        strongest_finding = (
            global_brand.get(
                "strongest_finding"
            )
            or {}
        )

        brand_name = strongest_finding.get(
            "brand_name",
            "an indexed organization",
        )

        finding_reason = strongest_finding.get(
            "reason"
        )

        if finding_reason:
            reasons.append(
                "Global Brand Intelligence: "
                + str(
                    finding_reason
                )
            )

        reasons.append(
            "Global Brand Intelligence: The hostname may "
            f"impersonate {brand_name}. Brand evidence added "
            "risk and prevented positive infrastructure history "
            "from lowering the verdict."
        )

    elif official_brand_domain:
        official_owner = (
            global_brand.get(
                "official_owner"
            )
            or {}
        )

        reasons.append(
            "Global Brand Intelligence: The hostname matches "
            "a recorded official domain for "
            f"{official_owner.get('brand_name', 'an organization')}. "
            "This confirms identity evidence only and does not "
            "guarantee that the page or email is safe."
        )

    if (
        organization_adjustment_blocked
    ):
        reasons.append(
            "Organization Intelligence: Positive identity "
            "evidence was prevented from lowering risk because "
            "independent phishing indicators were detected."
        )

    if positive_adjustment_blocked:
        reasons.append(
            "Infrastructure history was not allowed to offset "
            "brand impersonation or other strong phishing evidence."
        )

    unavailable_sources = []

    for name, lookup in (
        (
            "Organization Intelligence",
            organization_lookup,
        ),
        (
            "Global Brand Intelligence",
            global_brand_lookup,
        ),
        (
            "RDAP",
            rdap_lookup,
        ),
        (
            "Certificate Transparency",
            ct_lookup,
        ),
        (
            "DNS Intelligence",
            dns_lookup,
        ),
        (
            "IP and ASN Intelligence",
            ip_asn_lookup,
        ),
        (
            "ThreatFox URL Intelligence",
            threatfox_url_lookup,
        ),
        (
            "ThreatFox Domain Intelligence",
            threatfox_domain_lookup,
        ),
    ):
        if not lookup[
            "available"
        ]:
            unavailable_sources.append(
                {
                    "source": name,
                    "error": lookup[
                        "error"
                    ],
                }
            )

    return {
        "input": value,
        "url": url,
        "hostname": hostname,
        "final_score": final_score,
        "base_hybrid_score": round(
            base_score,
            2,
        ),
        "total_intelligence_adjustment": round(
            total_adjustment,
            2,
        ),
        "risk_level": risk_level,
        "classification": classification,
        "confidence_percentage": (
            confidence
        ),
        "confidence_level": (
            confidence_level(
                confidence
            )
        ),
        "is_suspicious": (
            final_score >= 35
        ),
        "is_phishing": (
            final_score >= 70
        ),
        "recommendation": (
            recommendation_for_score(
                final_score
            )
        ),
        "reasons": reasons,
        "unavailable_sources": (
            unavailable_sources
        ),
        "hybrid_detection": hybrid,
        "organization_intelligence": {
            **organization,
            "requested_score_adjustment": (
                organization_requested_adjustment
            ),
            "applied_score_adjustment": (
                organization_applied_adjustment
            ),
            "adjustment_blocked": (
                organization_adjustment_blocked
            ),
        },
        "global_brand_intelligence": {
            **global_brand,
            "requested_score_adjustment": (
                global_brand_requested_adjustment
            ),
            "applied_score_adjustment": (
                global_brand_applied_adjustment
            ),
        },
        "rdap_intelligence": {
            "observation": (
                rdap_observation
            ),
            "evidence": (
                rdap_evidence
            ),
            "applied_score_adjustment": (
                rdap_adjustment
            ),
        },
        "certificate_transparency": {
            "observation": (
                ct_observation
            ),
            "evidence": (
                ct_evidence
            ),
            "applied_score_adjustment": (
                ct_adjustment
            ),
        },
        "dns_intelligence": {
            "observation": (
                dns_observation
            ),
            "evidence": (
                dns_evidence
            ),
            "applied_score_adjustment": (
                dns_adjustment
            ),
        },
        "ip_asn_intelligence": {
            "observation": (
                ip_asn_observation
            ),
            "evidence": (
                ip_asn_evidence
            ),
            "applied_score_adjustment": (
                ip_asn_adjustment
            ),
        },
        "threatfox_intelligence": {
            "matched": threatfox_matched,
            "applied_score_adjustment": (
                threatfox_adjustment
            ),
            "url_lookup": {
                "observation": (
                    threatfox_url_observation
                ),
                "evidence": (
                    threatfox_url_evidence
                ),
            },
            "domain_lookup": {
                "observation": (
                    threatfox_domain_observation
                ),
                "evidence": (
                    threatfox_domain_evidence
                ),
            },
        },
        "evidence_summary": {
            "strong_phishing_signals": (
                strong_signal_count
            ),
            "weak_phishing_signals": (
                weak_signal_count
            ),
            "brand_impersonation": (
                brand_impersonation
            ),
            "legacy_brand_impersonation": (
                legacy_brand_impersonation
            ),
            "global_brand_impersonation": (
                global_brand_impersonation
            ),
            "official_brand_domain": (
                official_brand_domain
            ),
            "organization_matched": bool(
                organization.get(
                    "matched",
                    False,
                )
            ),
            "rdap_available": bool(
                rdap_evidence.get(
                    "available",
                    False,
                )
            ),
            "certificate_history_available": bool(
                ct_evidence.get(
                    "available",
                    False,
                )
            ),
            "dns_available": bool(
                dns_evidence.get(
                    "available",
                    False,
                )
            ),
            "ip_asn_available": bool(
                ip_asn_evidence.get(
                    "available",
                    False,
                )
            ),
            "public_ip_count": len(
                (
                    ip_asn_observation
                    or {}
                ).get(
                    "public_addresses",
                    [],
                )
            ),
            "origin_asn_count": len(
                (
                    ip_asn_observation
                    or {}
                ).get(
                    "unique_asns",
                    [],
                )
            ),
            "threatfox_matched": (
                threatfox_matched
            ),
            "threatfox_url_match": bool(
                threatfox_url_evidence.get(
                    "matched",
                    False,
                )
            ),
            "threatfox_domain_match": bool(
                threatfox_domain_evidence.get(
                    "matched",
                    False,
                )
            ),
        },
        "limitations": [
            (
                "A legitimate organization may have a compromised "
                "website or mailbox."
            ),
            (
                "A valid registration or TLS certificate does not "
                "prove that a domain is safe."
            ),
            (
                "Missing RDAP, Certificate Transparency or DNS data "
                "does not prove maliciousness."
            ),
            (
                "Newly registered domains are not automatically "
                "classified as phishing."
            ),
            (
                "The model is not retrained from unlabeled domain "
                "observations."
            ),
            (
                "ASN and hosting-provider ownership identify "
                "infrastructure, not necessarily the organization "
                "controlling the domain."
            ),
            (
                "ThreatFox focuses on malware-associated IOCs "
                "and does not cover every phishing campaign."
            ),
            (
                "A ThreatFox no-match result does not prove that "
                "a URL or domain is safe."
            ),
        ],
    }

def analyze_unified_domain_profile(
    value: str,
    *,
    force_refresh: bool = False,
    include_ct_subdomains: bool = False,
):
    """
    Public domain-profile entry point with official-domain and
    threat-intelligence relevance safety controls.
    """
    legacy_result = _analyze_unified_domain_profile_legacy(
        value,
        force_refresh=force_refresh,
        include_ct_subdomains=include_ct_subdomains,
    )

    return legacy_result

