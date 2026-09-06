from __future__ import annotations

from app.analyst.analyst_engine import (
    analyze_evidence,
)
from app.analyst.evidence import (
    InvestigationEvidence,
)
from app.reports.ioc_extractor import (
    extract_iocs,
)
from app.reports.models import (
    InvestigationReport,
    ReportFinding,
    TimelineEvent,
)
from app.reports.timeline import (
    build_timeline,
)


def build_investigation_report(
    evidence: InvestigationEvidence,
) -> InvestigationReport:
    """
    Build the ONE canonical investigation report.

    Exporters must consume this object.
    They must not rerun detection or AI.
    """

    analyst = analyze_evidence(
        evidence
    )

    findings = [
        ReportFinding(
            title=item.title,
            explanation=item.explanation,
            severity=item.severity,
            evidence_ids=list(
                item.evidence_ids
            ),
        )

        for item in analyst.findings
    ]

    timeline = build_timeline(
        evidence
    )

    timeline.append(
        TimelineEvent(
            timestamp=evidence.created_at,
            event_type="ai_analysis",
            title="Grounded AI analysis completed",
            description=(
                "The AI Security Analyst interpreted "
                "the supplied deterministic evidence."
            ),
            source=analyst.model,
        )
    )

    timeline.append(
        TimelineEvent(
            timestamp=evidence.created_at,
            event_type="report_generation",
            title="Investigation report generated",
            description=(
                "The canonical InvestigationReport "
                "object was created."
            ),
            source="report_engine",
        )
    )

    best_identity = (
        evidence.identity.get(
            "best_match"
        )
        or {}
    )

    return InvestigationReport(
        investigation_id=(
            evidence.investigation_id
        ),

        created_at=(
            evidence.created_at
        ),

        target=(
            evidence.target
        ),

        target_type=(
            evidence.target_type
        ),

        verdict=(
            analyst.verdict
        ),

        confidence=float(
            analyst.confidence
        ),

        severity=float(
            evidence.core.get(
                "severity",
                0.0,
            )
        ),

        risk_level=str(
            evidence.core.get(
                "risk_level",
                "UNKNOWN",
            )
        ),

        executive_summary=(
            analyst.executive_summary
        ),

        findings=findings,

        identity={
            "known": (
                evidence.identity.get(
                    "identity_known"
                )
            ),

            "canonical_domain": (
                evidence.identity.get(
                    "canonical_domain"
                )
            ),

            "organization": (
                best_identity.get(
                    "organization"
                )
            ),

            "state": (
                best_identity.get(
                    "evidence_state",
                    "unknown",
                )
            ),

            "confidence": (
                best_identity.get(
                    "confidence_score",
                    0.0,
                )
            ),

            "sources": (
                best_identity.get(
                    "sources",
                    [],
                )
            ),
        },

        mitre_attack=list(
            analyst.mitre_attack
        ),

        iocs=extract_iocs(
            evidence
        ),

        timeline=timeline,

        recommendations=list(
            analyst.recommended_actions
        ),

        limitations=list(
            analyst.limitations
        ),

        evidence=(
            evidence.to_dict()
        ),

        analyst_model=(
            analyst.model
        ),

        metadata={
            "core_release": (
                evidence.metadata.get(
                    "core_release"
                )
            ),

            "grounded_ai": (
                analyst.grounded
            ),

            "security_facts_generated_by_ai": (
                False
            ),

            "report_schema_version": (
                "1.0"
            ),
        },
    )
