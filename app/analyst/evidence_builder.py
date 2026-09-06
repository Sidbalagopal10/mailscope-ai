from __future__ import annotations

import hashlib
from typing import Any

from app.analyst.evidence import (
    EvidenceFinding,
    InvestigationEvidence,
    utc_now,
)
from app.global_entity_registry.identity.explanation import (
    explain_identity,
)
from app.services.risk_engine import (
    analyze_url,
)
from app.threat_enrichment.orchestrator import (
    enrich_target,
)


def _investigation_id(
    target: str,
) -> str:
    digest = hashlib.sha256(
        target.encode(
            "utf-8"
        )
    ).hexdigest()[:12]

    return (
        "inv-"
        + digest
    )


def _core_evidence(
    url: str,
) -> dict[str, Any]:
    result = analyze_url(
        url
    )

    return {
        "url": result.url,

        "severity": float(
            result.severity
        ),

        "risk_level": (
            result.risk_level
        ),

        "is_suspicious": bool(
            result.is_suspicious
        ),

        "reasons": list(
            result.reasons
        ),
    }


def _identity_evidence(
    url: str,
) -> dict[str, Any]:
    try:
        return explain_identity(
            url
        )

    except Exception as error:
        return {
            "identity_known": False,

            "best_match": None,

            "matches": [],

            "error": (
                f"{type(error).__name__}: "
                f"{error}"
            ),
        }



def _threat_intelligence_evidence(
    url: str,
) -> dict[str, Any]:
    """
    Collect deterministic threat-intelligence evidence.

    IMPORTANT:
    Threat intelligence does not modify Core Engine
    severity or independently create a phishing verdict.

    Provider/orchestrator failure remains neutral and
    must not prevent an investigation from being built.
    """

    try:
        enrichment = enrich_target(
            url,
            force_refresh=False,
            include_ct_subdomains=False,
        )

        return enrichment.to_dict()

    except Exception as error:
        return {
            "target": url,

            "sources": [],

            "summary": {
                "source_count": 0,
                "available_sources": 0,
                "failed_sources": 1,
            },

            "error": (
                f"{type(error).__name__}: "
                f"{error}"
            ),

            "metadata": {
                "orchestrator_version": (
                    "2.0.0"
                ),

                "core_engine_modified": False,

                "ai_used": False,

                "threat_intelligence_is_evidence": (
                    True
                ),

                "provider_failure_is_neutral": (
                    True
                ),
            },
        }



def _findings_from_core(
    core: dict[str, Any],
) -> list[EvidenceFinding]:
    findings = []

    severity = float(
        core.get(
            "severity",
            0.0,
        )
    )

    policy_only_reasons = {
        (
            "Established organizational identity does not "
            "override independent malicious evidence."
        ),
    }

    for reason in core.get(
        "reasons",
        [],
    ):
        reason_text = str(
            reason
        ).strip()

        # Core Engine may include explanatory policy text in
        # its reason list. Policy statements describe detector
        # behavior; they are not observations about the target.
        #
        # Preserve them in evidence.core, but do not assign
        # them an E# security-evidence identifier.
        if reason_text in policy_only_reasons:
            continue

        findings.append(
            EvidenceFinding(
                category="url_analysis",

                title=reason_text,

                description=reason_text,

                severity=(
                    "high"
                    if severity >= 6
                    else (
                        "medium"
                        if severity >= 4
                        else "low"
                    )
                ),

                source="core_engine_v1",

                confidence=None,
            )
        )

    return findings


def _findings_from_identity(
    identity: dict[str, Any],
) -> list[EvidenceFinding]:
    findings = []

    best = identity.get(
        "best_match"
    )

    if not best:
        findings.append(
            EvidenceFinding(
                category="identity",

                title=(
                    "Organizational identity "
                    "not established"
                ),

                description=(
                    "The registry does not currently "
                    "establish an organization-domain "
                    "identity for this hostname. "
                    "Unknown identity is neutral and "
                    "does not itself imply maliciousness."
                ),

                severity="info",

                source=(
                    "identity_confidence_engine"
                ),

                confidence=0.0,
            )
        )

        return findings

    state = str(
        best.get(
            "evidence_state",
            "unknown",
        )
    )

    confidence = float(
        best.get(
            "confidence_score",
            0.0,
        )
    )

    organization = best.get(
        "organization"
    )

    if state == "verified":
        title = (
            "Organizational identity verified"
        )

        severity = "info"

    elif state == "supported":
        title = (
            "Organizational identity supported"
        )

        severity = "info"

    elif state == "conflicting":
        title = (
            "Organizational identity sources conflict"
        )

        severity = "medium"

    else:
        title = (
            "Organizational identity unknown"
        )

        severity = "info"

    findings.append(
        EvidenceFinding(
            category="identity",

            title=title,

            description=(
                f"Identity state: {state}. "
                f"Organization: "
                f"{organization or 'unknown'}. "
                f"Confidence: {confidence:.1f}/100."
            ),

            severity=severity,

            source=(
                "identity_confidence_engine"
            ),

            confidence=(
                confidence / 100.0
            ),

            raw={
                "state": state,

                "organization": (
                    organization
                ),

                "sources": best.get(
                    "sources",
                    [],
                ),

                "conflicting_domains": (
                    best.get(
                        "conflicting_domains",
                        [],
                    )
                ),
            },
        )
    )

    return findings



def _nested_dict(
    value: Any,
) -> dict[str, Any]:
    if isinstance(value, dict):
        return value

    return {}


def _findings_from_intelligence(
    intelligence: dict[str, Any],
) -> list[EvidenceFinding]:
    """
    Convert normalized threat intelligence into concise,
    deterministic findings suitable for grounded AI use.

    SECURITY BOUNDARY:
    - Provider failure is neutral.
    - Absence of threat intelligence is neutral.
    - Threat-feed evidence does not modify Core Engine risk.
    - Only normalized facts become analyst evidence.
    - Raw provider payloads are not passed directly to the AI.
    """

    findings: list[EvidenceFinding] = []

    sources = intelligence.get(
        "sources",
        [],
    )

    if not isinstance(sources, list):
        return findings

    for source in sources:
        if not isinstance(source, dict):
            continue

        name = str(
            source.get(
                "source",
                "unknown",
            )
        )

        status = str(
            source.get(
                "status",
                "unavailable",
            )
        )

        evidence = _nested_dict(
            source.get(
                "evidence"
            )
        )

        # --------------------------------------------------
        # Provider failures / missing data remain neutral.
        # They are recorded as limitations in the raw
        # intelligence object, not security findings.
        # --------------------------------------------------

        if status != "available":
            continue

        # --------------------------------------------------
        # THREATFOX
        # Only relevance-validated exact/related IOC
        # evidence is allowed to become a threat finding.
        # --------------------------------------------------

        if name == "threatfox":
            provider_matched = bool(
                evidence.get(
                    "matched",
                    False,
                )
            )

            relevance_validated = bool(
                evidence.get(
                    "relevance_validated",
                    False,
                )
            )

            relevant_exact_match = bool(
                evidence.get(
                    "relevant_exact_match",
                    False,
                )
            )

            relevant_iocs = evidence.get(
                "relevant_iocs",
                [],
            )

            # A candidate IOC being equal to the requested
            # hostname is not enough. ThreatFox itself must
            # have returned an actual positive match.
            #
            # This protects against self-match artifacts where
            # the submitted query value is later rediscovered
            # by relevance normalization.
            relevant = (
                provider_matched
                and relevance_validated
                and relevant_exact_match
            )

            if relevant:
                count = (
                    len(relevant_iocs)
                    if isinstance(
                        relevant_iocs,
                        list,
                    )
                    else 0
                )

                findings.append(
                    EvidenceFinding(
                        category=(
                            "threat_intelligence"
                        ),

                        title=(
                            "ThreatFox relevant IOC "
                            "match observed"
                        ),

                        description=(
                            "ThreatFox intelligence "
                            "contains a relevance-validated "
                            "IOC match for the investigated "
                            f"target. Relevant IOC count: "
                            f"{count}."
                        ),

                        severity="high",

                        source="threatfox",

                        confidence=None,

                        raw={
                            "provider_matched": (
                                True
                            ),

                            "relevant_exact_match": (
                                True
                            ),

                            "relevant_ioc_count": (
                                count
                            ),

                            "relevance_validated": (
                                evidence.get(
                                    "relevance_validated"
                                )
                            ),
                        },
                    )
                )

            continue

        # --------------------------------------------------
        # VIRUSTOTAL
        # Use only normalized aggregate detection counts.
        # The AI does not receive the complete VT payload.
        # --------------------------------------------------

        if name == "virustotal":
            available = evidence.get(
                "available"
            )

            matched = bool(
                evidence.get(
                    "matched",
                    False,
                )
            )

            malicious = evidence.get(
                "maximum_malicious",
                0,
            )

            suspicious = evidence.get(
                "maximum_suspicious",
                0,
            )

            try:
                malicious_count = int(
                    malicious or 0
                )
            except (
                TypeError,
                ValueError,
            ):
                malicious_count = 0

            try:
                suspicious_count = int(
                    suspicious or 0
                )
            except (
                TypeError,
                ValueError,
            ):
                suspicious_count = 0

            if (
                available is not False
                and (
                    matched
                    or malicious_count > 0
                    or suspicious_count > 0
                )
            ):
                severity = (
                    "high"
                    if malicious_count > 0
                    else "medium"
                )

                findings.append(
                    EvidenceFinding(
                        category=(
                            "threat_intelligence"
                        ),

                        title=(
                            "VirusTotal detections "
                            "observed"
                        ),

                        description=(
                            "VirusTotal normalized "
                            "intelligence reported "
                            f"{malicious_count} malicious "
                            "and "
                            f"{suspicious_count} suspicious "
                            "detections for the investigated "
                            "target or normalized lookup."
                        ),

                        severity=severity,

                        source="virustotal",

                        confidence=None,

                        raw={
                            "matched": matched,

                            "malicious_detections": (
                                malicious_count
                            ),

                            "suspicious_detections": (
                                suspicious_count
                            ),
                        },
                    )
                )

            continue

        # --------------------------------------------------
        # RDAP
        # Domain registration data is contextual evidence.
        # We intentionally do NOT convert "young domain"
        # into a phishing finding here because the existing
        # deterministic engine already owns risk semantics.
        # --------------------------------------------------

        if name == "rdap":
            observation = _nested_dict(
                evidence.get(
                    "observation"
                )
            )

            age = observation.get(
                "domain_age_days"
            )

            if age is not None:
                try:
                    age_days = int(
                        age
                    )
                except (
                    TypeError,
                    ValueError,
                ):
                    age_days = None

                if age_days is not None:
                    findings.append(
                        EvidenceFinding(
                            category=(
                                "infrastructure"
                            ),

                            title=(
                                "Domain registration "
                                "context available"
                            ),

                            description=(
                                "RDAP registration "
                                "intelligence reports a "
                                f"domain age of {age_days} "
                                "days. Domain age is "
                                "contextual evidence and is "
                                "not independently proof of "
                                "maliciousness."
                            ),

                            severity="info",

                            source="rdap",

                            confidence=None,

                            raw={
                                "domain_age_days": (
                                    age_days
                                )
                            },
                        )
                    )

            continue

        # --------------------------------------------------
        # DNS / CT / IP-ASN
        #
        # These providers remain available in the complete
        # intelligence object, but we do not manufacture
        # analyst findings from them unless a stable,
        # explicitly normalized security fact exists.
        #
        # This prevents raw infrastructure metadata from
        # becoming accidental suspicion.
        # --------------------------------------------------

    return findings



def build_url_evidence(
    url: str,
) -> InvestigationEvidence:
    """
    Build the evidence package.

    IMPORTANT:
    No LLM is called here.

    Every value comes from deterministic
    project components.
    """

    core = _core_evidence(
        url
    )

    identity = (
        _identity_evidence(
            url
        )
    )

    intelligence = (
        _threat_intelligence_evidence(
            url
        )
    )

    findings = []

    findings.extend(
        _findings_from_core(
            core
        )
    )

    findings.extend(
        _findings_from_identity(
            identity
        )
    )

    findings.extend(
        _findings_from_intelligence(
            intelligence
        )
    )

    return InvestigationEvidence(
        investigation_id=(
            _investigation_id(
                url
            )
        ),

        target=url,

        target_type="url",

        created_at=utc_now(),

        core=core,

        identity=identity,

        findings=findings,

        intelligence=intelligence,

        metadata={
            "core_release": (
                "core-engine-v1.0"
            ),

            "ai_used_for_evidence": (
                False
            ),

            "evidence_grounded": (
                True
            ),

            "threat_enrichment_version": (
                "2.0.0"
            ),

            "threat_intelligence_affects_core": (
                False
            ),
        },
    )
