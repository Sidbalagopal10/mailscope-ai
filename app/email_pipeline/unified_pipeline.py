from __future__ import annotations

from typing import Any

from app.domain_intelligence.enriched_profile import (
    analyze_enriched_domain_profile,
)
from app.email_authentication.header_parser import (
    parse_email_authentication,
)
from app.email_security.contextual_decision import (
    contextual_email_decision,
)
from app.gmail_actions.label_planner import (
    build_label_plan_for_message,
)
from app.gmail_observation.observer import (
    basic_link_risk,
    extract_urls,
    should_deep_analyze_links,
)
from app.model_governance.active_calibrator import (
    apply_active_calibrator,
)


def clamp(
    value: float,
    minimum: float = 0.0,
    maximum: float = 100.0,
) -> float:
    return max(
        minimum,
        min(
            float(value),
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


def safe_deep_url_analysis(
    url: str,
    *,
    force_refresh: bool = False,
    enable_virustotal: bool = True,
) -> dict[str, Any]:
    try:
        result = analyze_enriched_domain_profile(
            url,
            force_refresh=force_refresh,
            include_ct_subdomains=False,
            enable_virustotal=enable_virustotal,
        )

        return {
            "url": url,
            "available": True,
            "error": None,
            "final_score": float(
                result.get(
                    "final_score",
                    0.0,
                )
                or 0.0
            ),
            "risk_level": result.get(
                "risk_level",
                "unknown",
            ),
            "classification": result.get(
                "classification",
                "unknown",
            ),
            "is_phishing": bool(
                result.get(
                    "is_phishing",
                    False,
                )
            ),
            "reasons": list(
                result.get(
                    "reasons",
                    [],
                )
                or []
            ),
            "evidence_summary": dict(
                result.get(
                    "evidence_summary",
                    {},
                )
                or {}
            ),
            "global_brand_intelligence": dict(
                result.get(
                    "global_brand_intelligence",
                    {},
                )
                or {}
            ),
            "threatfox_intelligence": dict(
                result.get(
                    "threatfox_intelligence",
                    {},
                )
                or {}
            ),
            "virustotal_intelligence": dict(
                result.get(
                    "virustotal_intelligence",
                    {},
                )
                or {}
            ),
            "organization_intelligence": dict(
                result.get(
                    "organization_intelligence",
                    {},
                )
                or {}
            ),
            "rdap_intelligence": dict(
                result.get(
                    "rdap_intelligence",
                    {},
                )
                or {}
            ),
            "dns_intelligence": dict(
                result.get(
                    "dns_intelligence",
                    {},
                )
                or {}
            ),
            "certificate_transparency": dict(
                result.get(
                    "certificate_transparency",
                    {},
                )
                or {}
            ),
            "ip_asn_intelligence": dict(
                result.get(
                    "ip_asn_intelligence",
                    {},
                )
                or {}
            ),
            "unavailable_sources": list(
                result.get(
                    "unavailable_sources",
                    [],
                )
                or []
            ),
            "important_limitations": list(
                result.get(
                    "important_limitations",
                    [],
                )
                or []
            ),
        }

    except Exception as error:
        return {
            "url": url,
            "available": False,
            "error": str(
                error
            ),
            "final_score": 0.0,
            "risk_level": "unknown",
            "classification": "unavailable",
            "is_phishing": False,
            "reasons": [],
            "evidence_summary": {},
            "global_brand_intelligence": {},
            "threatfox_intelligence": {},
            "virustotal_intelligence": {},
            "organization_intelligence": {},
            "rdap_intelligence": {},
            "dns_intelligence": {},
            "certificate_transparency": {},
            "ip_asn_intelligence": {},
            "unavailable_sources": [],
            "important_limitations": [],
        }


def analyze_urls_selectively(
    urls: list[str],
    *,
    preliminary_risk_level: str,
    basic_link_score: float,
    maximum_urls: int = 5,
    force_refresh: bool = False,
    enable_virustotal: bool = True,
) -> dict[str, Any]:
    required = should_deep_analyze_links(
        preliminary_risk_level=(
            preliminary_risk_level
        ),
        basic_link_score=(
            basic_link_score
        ),
        urls=urls,
    )

    if not required:
        return {
            "performed": False,
            "reason": (
                "Preliminary message and URL evidence did not "
                "justify external deep analysis."
            ),
            "requested_url_count": len(
                urls
            ),
            "analyzed_url_count": 0,
            "skipped_url_count": len(
                urls
            ),
            "highest_score": 0.0,
            "highest_risk_url": None,
            "available_result_count": 0,
            "failed_result_count": 0,
            "results": [],
        }

    safe_limit = max(
        1,
        min(
            int(maximum_urls),
            10,
        ),
    )

    selected_urls = urls[:safe_limit]

    results = [
        safe_deep_url_analysis(
            url,
            force_refresh=force_refresh,
            enable_virustotal=(
                enable_virustotal
            ),
        )
        for url in selected_urls
    ]

    available_results = [
        result
        for result in results
        if result.get(
            "available",
            False,
        )
    ]

    highest_result = max(
        available_results,
        key=lambda item: float(
            item.get(
                "final_score",
                0.0,
            )
            or 0.0
        ),
        default=None,
    )

    highest_score = (
        float(
            highest_result.get(
                "final_score",
                0.0,
            )
            or 0.0
        )
        if highest_result
        else 0.0
    )

    return {
        "performed": True,
        "reason": (
            "Preliminary message or URL evidence justified "
            "selective deep analysis."
        ),
        "requested_url_count": len(
            urls
        ),
        "analyzed_url_count": len(
            results
        ),
        "skipped_url_count": max(
            0,
            len(urls) - len(results),
        ),
        "highest_score": round(
            highest_score,
            2,
        ),
        "highest_risk_url": (
            highest_result.get(
                "url"
            )
            if highest_result
            else None
        ),
        "available_result_count": len(
            available_results
        ),
        "failed_result_count": sum(
            1
            for result in results
            if not result.get(
                "available",
                False,
            )
        ),
        "results": results,
    }


def collect_deep_signals(
    deep_analysis: dict[str, Any],
) -> dict[str, Any]:
    results = deep_analysis.get(
        "results",
        [],
    )

    threatfox_matches = [
        result.get(
            "url"
        )
        for result in results
        if (
            result.get(
                "threatfox_intelligence",
                {},
            )
            or {}
        ).get(
            "matched",
            False,
        )
    ]

    virustotal_matches = [
        result.get(
            "url"
        )
        for result in results
        if (
            result.get(
                "virustotal_intelligence",
                {},
            )
            or {}
        ).get(
            "matched",
            False,
        )
    ]

    brand_impersonation_urls = [
        result.get(
            "url"
        )
        for result in results
        if (
            result.get(
                "global_brand_intelligence",
                {},
            )
            or {}
        ).get(
            "impersonation_detected",
            False,
        )
    ]

    official_domain_urls = [
        result.get(
            "url"
        )
        for result in results
        if (
            result.get(
                "global_brand_intelligence",
                {},
            )
            or {}
        ).get(
            "official_domain_match",
            False,
        )
    ]

    return {
        "threatfox_match": bool(
            threatfox_matches
        ),
        "threatfox_urls": (
            threatfox_matches
        ),
        "virustotal_match": bool(
            virustotal_matches
        ),
        "virustotal_urls": (
            virustotal_matches
        ),
        "brand_impersonation": bool(
            brand_impersonation_urls
        ),
        "brand_impersonation_urls": (
            brand_impersonation_urls
        ),
        "official_domain_urls": (
            official_domain_urls
        ),
    }


def apply_hard_security_floors(
    *,
    score: float,
    deep_signals: dict[str, Any],
    contextual_decision_result: dict[str, Any],
) -> tuple[
    float,
    list[str],
]:
    adjusted_score = float(
        score
    )

    reasons: list[str] = []

    if deep_signals.get(
        "threatfox_match"
    ):
        adjusted_score = max(
            adjusted_score,
            85.0,
        )

        reasons.append(
            "ThreatFox malware-associated IOC evidence "
            "enforced a critical-risk score floor."
        )

    if deep_signals.get(
        "virustotal_match"
    ):
        vt_maximum = max(
            (
                int(
                    (
                        result.get(
                            "virustotal_intelligence",
                            {},
                        )
                        or {}
                    ).get(
                        "maximum_malicious",
                        0,
                    )
                    or 0
                )
                for result in contextual_decision_result.get(
                    "_deep_results",
                    [],
                )
            ),
            default=0,
        )

        if vt_maximum >= 10:
            adjusted_score = max(
                adjusted_score,
                90.0,
            )

            reasons.append(
                "At least ten VirusTotal engines reported "
                "malicious activity."
            )

        elif vt_maximum >= 5:
            adjusted_score = max(
                adjusted_score,
                82.0,
            )

            reasons.append(
                "Multiple VirusTotal engines reported "
                "malicious activity."
            )

        elif vt_maximum >= 2:
            adjusted_score = max(
                adjusted_score,
                70.0,
            )

            reasons.append(
                "More than one VirusTotal engine reported "
                "malicious activity."
            )

    if deep_signals.get(
        "brand_impersonation"
    ):
        adjusted_score = max(
            adjusted_score,
            75.0,
        )

        reasons.append(
            "Confirmed brand-impersonation evidence enforced "
            "a high-risk score floor."
        )

    authentication_verdict = (
        contextual_decision_result.get(
            "authentication_evidence",
            {},
        )
        or {}
    ).get(
        "verdict"
    )

    high_risk_intents = set(
        (
            contextual_decision_result.get(
                "message_context",
                {},
            )
            or {}
        ).get(
            "intent",
            {},
        ).get(
            "high_risk_intents",
            [],
        )
        or []
    )

    if (
        authentication_verdict
        == "authentication_failed"
        and high_risk_intents
    ):
        adjusted_score = max(
            adjusted_score,
            75.0,
        )

        reasons.append(
            "Sender authentication failure combined with a "
            "high-risk request intent enforced a high-risk floor."
        )

    return (
        clamp(
            adjusted_score
        ),
        reasons,
    )


def build_message_for_label_planner(
    *,
    message_id: str | None,
    thread_id: str | None,
    subject: str,
    sender_address: str | None,
    final_decision: dict[str, Any],
    deep_analysis: dict[str, Any],
) -> dict[str, Any]:
    return {
        "message_id": (
            message_id
            or "analysis-only-message"
        ),
        "thread_id": thread_id,
        "subject": subject,
        "sender_address": (
            sender_address
        ),
        "contextual_decision": (
            final_decision
        ),
        "deep_link_analysis": (
            deep_analysis
        ),
    }


def analyze_email_security_pipeline(
    *,
    subject: str | None,
    body: str | None,
    headers: Any = None,
    urls: list[str] | None = None,
    message_id: str | None = None,
    thread_id: str | None = None,
    sender_address: str | None = None,
    known_sender: bool = False,
    existing_thread: bool = False,
    sender_domain_verified: bool = False,
    attachment_risk_score: float = 0.0,
    maximum_deep_urls: int = 5,
    force_refresh: bool = False,
    enable_virustotal: bool = True,
) -> dict[str, Any]:
    """
    Canonical end-to-end email-security analysis.

    This function does not modify Gmail.
    """
    normalized_subject = str(
        subject or ""
    )

    normalized_body = str(
        body or ""
    )

    authentication = (
        parse_email_authentication(
            headers or []
        )
    )

    extracted_urls = extract_urls(
        normalized_body
    )

    combined_urls: list[str] = []

    for url in list(
        urls or []
    ) + extracted_urls:
        normalized = str(
            url or ""
        ).strip()

        if (
            normalized
            and normalized
            not in combined_urls
        ):
            combined_urls.append(
                normalized
            )

    basic_link_observation = (
        basic_link_risk(
            combined_urls
        )
    )

    preliminary_decision = (
        contextual_email_decision(
            subject=normalized_subject,
            body=normalized_body,
            authentication=authentication,
            link_risk_score=(
                basic_link_observation.get(
                    "risk_score",
                    0.0,
                )
            ),
            attachment_risk_score=(
                clamp(
                    attachment_risk_score
                )
            ),
            known_sender=known_sender,
            existing_thread=(
                existing_thread
            ),
            sender_domain_verified=(
                sender_domain_verified
            ),
        )
    )

    deep_analysis = analyze_urls_selectively(
        combined_urls,
        preliminary_risk_level=(
            preliminary_decision.get(
                "risk_level",
                "low",
            )
        ),
        basic_link_score=float(
            basic_link_observation.get(
                "risk_score",
                0.0,
            )
            or 0.0
        ),
        maximum_urls=(
            maximum_deep_urls
        ),
        force_refresh=force_refresh,
        enable_virustotal=(
            enable_virustotal
        ),
    )

    combined_link_score = max(
        float(
            basic_link_observation.get(
                "risk_score",
                0.0,
            )
            or 0.0
        ),
        float(
            deep_analysis.get(
                "highest_score",
                0.0,
            )
            or 0.0
        ),
    )

    contextual_final = contextual_email_decision(
        subject=normalized_subject,
        body=normalized_body,
        authentication=authentication,
        link_risk_score=(
            combined_link_score
        ),
        attachment_risk_score=(
            clamp(
                attachment_risk_score
            )
        ),
        known_sender=known_sender,
        existing_thread=existing_thread,
        sender_domain_verified=(
            sender_domain_verified
        ),
    )

    contextual_final[
        "_deep_results"
    ] = deep_analysis.get(
        "results",
        [],
    )

    deep_signals = collect_deep_signals(
        deep_analysis
    )

    floored_score, floor_reasons = (
        apply_hard_security_floors(
            score=float(
                contextual_final.get(
                    "risk_score",
                    0.0,
                )
                or 0.0
            ),
            deep_signals=deep_signals,
            contextual_decision_result=(
                contextual_final
            ),
        )
    )

    contextual_final.pop(
        "_deep_results",
        None,
    )

    final_risk_level = risk_level_for_score(
        floored_score
    )

    final_classification = (
        classification_for_score(
            floored_score
        )
    )

    final_decision = {
        **contextual_final,
        "risk_score": round(
            floored_score,
            2,
        ),
        "risk_level": final_risk_level,
        "classification": (
            final_classification
        ),
        "is_phishing": bool(
            floored_score >= 60
        ),
        "security_floor_reasons": (
            floor_reasons
        ),
    }

    final_decision[
        "reasons"
    ] = list(
        final_decision.get(
            "reasons",
            [],
        )
        or []
    ) + floor_reasons

    calibrator = apply_active_calibrator(
        predicted_score=(
            final_decision[
                "risk_score"
            ]
        ),
        predicted_risk_level=(
            final_decision[
                "risk_level"
            ]
        ),
        predicted_classification=(
            final_decision[
                "classification"
            ]
        ),
    )

    planning_message = (
        build_message_for_label_planner(
            message_id=message_id,
            thread_id=thread_id,
            subject=normalized_subject,
            sender_address=(
                sender_address
            ),
            final_decision=(
                final_decision
            ),
            deep_analysis=(
                deep_analysis
            ),
        )
    )

    label_plan = (
        build_label_plan_for_message(
            planning_message
        )
    )

    evidence_summary = {
        "authentication_available": bool(
            (
                final_decision.get(
                    "authentication_evidence",
                    {},
                )
                or {}
            ).get(
                "available",
                False,
            )
        ),
        "authentication_verdict": (
            final_decision.get(
                "authentication_evidence",
                {},
            )
            or {}
        ).get(
            "verdict"
        ),
        "primary_intent": (
            final_decision.get(
                "message_context",
                {},
            )
            or {}
        ).get(
            "intent",
            {},
        ).get(
            "primary_intent"
        ),
        "urgency_detected": bool(
            (
                final_decision.get(
                    "message_context",
                    {},
                )
                or {}
            ).get(
                "urgency",
                {},
            ).get(
                "detected",
                False,
            )
        ),
        "url_count": len(
            combined_urls
        ),
        "deep_analysis_performed": bool(
            deep_analysis.get(
                "performed",
                False,
            )
        ),
        "deep_urls_analyzed": int(
            deep_analysis.get(
                "analyzed_url_count",
                0,
            )
            or 0
        ),
        "highest_url_score": float(
            deep_analysis.get(
                "highest_score",
                0.0,
            )
            or 0.0
        ),
        "threatfox_match": bool(
            deep_signals.get(
                "threatfox_match"
            )
        ),
        "virustotal_match": bool(
            deep_signals.get(
                "virustotal_match"
            )
        ),
        "brand_impersonation": bool(
            deep_signals.get(
                "brand_impersonation"
            )
        ),
        "known_sender": bool(
            known_sender
        ),
        "existing_thread": bool(
            existing_thread
        ),
        "sender_domain_verified": bool(
            sender_domain_verified
        ),
        "attachment_risk_score": (
            clamp(
                attachment_risk_score
            )
        ),
        "calibrator_available": bool(
            calibrator.get(
                "available",
                False,
            )
        ),
        "calibrator_applied": bool(
            calibrator.get(
                "applied",
                False,
            )
        ),
        "human_review_required": bool(
            label_plan.get(
                "human_review_required",
                False,
            )
        ),
    }

    return {
        "pipeline_version": "1.0.0",
        "analysis_only": True,
        "gmail_modified": False,
        "message": {
            "message_id": message_id,
            "thread_id": thread_id,
            "subject": normalized_subject,
            "sender_address": (
                sender_address
            ),
            "known_sender": bool(
                known_sender
            ),
            "existing_thread": bool(
                existing_thread
            ),
            "sender_domain_verified": bool(
                sender_domain_verified
            ),
        },
        "authentication": authentication,
        "urls": combined_urls,
        "basic_link_observation": (
            basic_link_observation
        ),
        "preliminary_decision": (
            preliminary_decision
        ),
        "deep_link_analysis": (
            deep_analysis
        ),
        "deep_signals": deep_signals,
        "combined_link_risk_score": (
            combined_link_score
        ),
        "final_decision": final_decision,
        "calibrator_advisory": calibrator,
        "label_recommendation": (
            label_plan
        ),
        "evidence_summary": (
            evidence_summary
        ),
        "important_limitations": [
            (
                "A legitimate sender account can be compromised."
            ),
            (
                "SPF, DKIM, and DMARC success do not prove that "
                "the requested action is safe."
            ),
            (
                "Threat-intelligence no-match results do not prove safety."
            ),
            (
                "VirusTotal and other external sources can be unavailable, "
                "stale, incomplete, or occasionally incorrect."
            ),
            (
                "The active calibrator is advisory and does not silently "
                "override the original detector."
            ),
            (
                "No Gmail modification occurs through this pipeline."
            ),
        ],
    }
