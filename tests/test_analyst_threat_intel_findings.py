from __future__ import annotations

from app.analyst.evidence_builder import (
    _findings_from_intelligence,
)
from app.analyst.evidence import (
    InvestigationEvidence,
)
from app.analyst.prompt_engine import (
    serialize_evidence,
)


def intelligence_with(
    source: str,
    evidence: dict,
    status: str = "available",
) -> dict:
    return {
        "sources": [
            {
                "source": source,
                "status": status,
                "summary": "test",
                "evidence": evidence,
            }
        ]
    }


def test_threatfox_exact_match_becomes_finding():
    findings = _findings_from_intelligence(
        intelligence_with(
            "threatfox",
            {
                "matched": True,
                "relevant_exact_match": True,
                "relevance_validated": True,
                "relevant_iocs": [
                    {
                        "ioc": (
                            "evil.example"
                        )
                    }
                ],
            },
        )
    )

    assert len(findings) == 1

    finding = findings[0]

    assert (
        finding.category
        == "threat_intelligence"
    )

    assert finding.source == "threatfox"
    assert finding.severity == "high"


def test_irrelevant_threatfox_match_is_not_finding():
    findings = _findings_from_intelligence(
        intelligence_with(
            "threatfox",
            {
                "matched": True,
                "original_match_claimed": True,
                "relevant_exact_match": False,
                "relevance_validated": True,
                "relevant_iocs": [],
            },
        )
    )

    assert findings == []


def test_virustotal_detection_becomes_finding():
    findings = _findings_from_intelligence(
        intelligence_with(
            "virustotal",
            {
                "available": True,
                "matched": True,
                "maximum_malicious": 4,
                "maximum_suspicious": 2,
            },
        )
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.source == "virustotal"
    assert finding.severity == "high"

    assert (
        finding.raw[
            "malicious_detections"
        ]
        == 4
    )


def test_clean_virustotal_does_not_create_threat_finding():
    findings = _findings_from_intelligence(
        intelligence_with(
            "virustotal",
            {
                "available": True,
                "matched": False,
                "maximum_malicious": 0,
                "maximum_suspicious": 0,
            },
        )
    )

    assert findings == []


def test_provider_failure_is_not_security_finding():
    findings = _findings_from_intelligence(
        intelligence_with(
            "virustotal",
            {
                "error": "timeout",
            },
            status="error",
        )
    )

    assert findings == []


def test_rdap_age_is_context_only():
    findings = _findings_from_intelligence(
        intelligence_with(
            "rdap",
            {
                "observation": {
                    "domain_age_days": 5
                }
            },
        )
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.source == "rdap"
    assert finding.severity == "info"

    assert (
        "not independently proof"
        in finding.description
    )


def test_intelligence_finding_receives_evidence_id():
    from app.analyst.evidence import (
        EvidenceFinding,
    )

    evidence = InvestigationEvidence(
        investigation_id="inv-test",

        target="https://example.com/",

        target_type="url",

        created_at=(
            "2026-09-05T00:00:00+00:00"
        ),

        core={
            "severity": 0.0,
            "risk_level": "LOW",
        },

        identity={},

        findings=[
            EvidenceFinding(
                category="identity",
                title="Identity unknown",
                description=(
                    "Unknown identity is neutral."
                ),
                severity="info",
                source="identity",
            ),

            EvidenceFinding(
                category=(
                    "threat_intelligence"
                ),
                title=(
                    "ThreatFox relevant IOC "
                    "match observed"
                ),
                description=(
                    "Relevant IOC observed."
                ),
                severity="high",
                source="threatfox",
            ),
        ],

        intelligence={},
    )

    package = serialize_evidence(
        evidence
    )

    assert (
        package["findings"][0][
            "evidence_id"
        ]
        == "E1"
    )

    assert (
        package["findings"][1][
            "evidence_id"
        ]
        == "E2"
    )

    assert (
        package["findings"][1][
            "source"
        ]
        == "threatfox"
    )


def test_raw_provider_payload_not_serialized_to_prompt():
    from app.analyst.evidence import (
        EvidenceFinding,
    )

    evidence = InvestigationEvidence(
        investigation_id="inv-test",

        target="https://example.com/",

        target_type="url",

        created_at=(
            "2026-09-05T00:00:00+00:00"
        ),

        core={
            "severity": 0.0,
            "risk_level": "LOW",
        },

        identity={},

        findings=[
            EvidenceFinding(
                category=(
                    "threat_intelligence"
                ),

                title=(
                    "VirusTotal detections observed"
                ),

                description=(
                    "VirusTotal reported normalized "
                    "detection counts."
                ),

                severity="high",

                source="virustotal",

                raw={
                    "secret_raw_payload": (
                        "SHOULD_NOT_REACH_PROMPT"
                    )
                },
            )
        ],

        intelligence={
            "raw_provider_data": (
                "ALSO_SHOULD_NOT_REACH_PROMPT"
            )
        },
    )

    package = serialize_evidence(
        evidence
    )

    serialized = str(
        package
    )

    assert (
        "SHOULD_NOT_REACH_PROMPT"
        not in serialized
    )

    assert (
        "ALSO_SHOULD_NOT_REACH_PROMPT"
        not in serialized
    )


def test_threatfox_self_match_artifact_is_rejected():
    """
    Regression:
    the submitted query itself may appear in relevant_iocs
    even though ThreatFox returned no actual IOC match.

    This must never become analyst threat evidence.
    """

    findings = _findings_from_intelligence(
        intelligence_with(
            "threatfox",
            {
                "matched": False,
                "original_match_claimed": False,
                "relevance_validated": True,
                "relevant_exact_match": True,
                "relevant_iocs": [
                    {
                        "raw_ioc": (
                            "research.microsoft.com"
                        ),
                        "candidate_host": (
                            "research.microsoft.com"
                        ),
                        "requested_host": (
                            "research.microsoft.com"
                        ),
                        "match_type": "exact",
                    }
                ],
            },
        )
    )

    assert findings == []


def test_threatfox_requires_provider_match():
    findings = _findings_from_intelligence(
        intelligence_with(
            "threatfox",
            {
                "matched": True,
                "relevance_validated": True,
                "relevant_exact_match": True,
                "relevant_iocs": [
                    {
                        "raw_ioc": (
                            "evil.example"
                        ),
                        "candidate_host": (
                            "evil.example"
                        ),
                        "requested_host": (
                            "evil.example"
                        ),
                        "match_type": "exact",
                    }
                ],
            },
        )
    )

    assert len(findings) == 1
    assert findings[0].source == "threatfox"

    assert (
        findings[0].raw[
            "provider_matched"
        ]
        is True
    )


def test_core_policy_reason_not_security_finding():
    from app.analyst.evidence_builder import (
        _findings_from_core,
    )

    core = {
        "severity": 0.0,
        "risk_level": "LOW",
        "is_suspicious": False,
        "reasons": [
            (
                "Established organizational identity "
                "does not override independent "
                "malicious evidence."
            )
        ],
    }

    findings = _findings_from_core(
        core
    )

    assert findings == []


def test_real_core_observation_remains_finding():
    from app.analyst.evidence_builder import (
        _findings_from_core,
    )

    core = {
        "severity": 6.0,
        "risk_level": "MODERATE",
        "is_suspicious": True,
        "reasons": [
            "Suspicious terms detected: login",
            "Possible brand impersonation: microsoft",
        ],
    }

    findings = _findings_from_core(
        core
    )

    assert len(findings) == 2

    titles = {
        finding.title
        for finding in findings
    }

    assert (
        "Suspicious terms detected: login"
        in titles
    )

    assert (
        "Possible brand impersonation: microsoft"
        in titles
    )
