from __future__ import annotations

from app.campaign_detection.models import (
    CampaignCandidate,
)
from app.campaign_detection.timeline import (
    build_campaign_timeline,
)
from app.reports.models import (
    InvestigationReport,
)


def report(
    investigation_id: str,
    timestamp: str,
) -> InvestigationReport:
    return InvestigationReport(
        investigation_id=(
            investigation_id
        ),
        created_at=timestamp,
        target="https://example.test/",
        target_type="url",
        verdict="suspicious",
        confidence=80.0,
        severity=6.0,
        risk_level="MODERATE",
        executive_summary="test",
        findings=[],
        identity={},
        mitre_attack=[],
        iocs=[],
        timeline=[],
        recommendations=[],
        limitations=[],
        evidence={},
        analyst_model="mock",
        metadata={},
    )


def test_campaign_timeline_is_chronological():
    candidate = CampaignCandidate(
        campaign_id="campaign-test",
        investigation_ids=[
            "INV-A",
            "INV-B",
            "INV-C",
        ],
        relationships=[],
        shared_artifacts=[],
        correlation_score=0.8,
        strength="moderate",
    )

    reports = [
        report(
            "INV-C",
            "2026-09-03T10:00:00+00:00",
        ),
        report(
            "INV-A",
            "2026-09-01T10:00:00+00:00",
        ),
        report(
            "INV-B",
            "2026-09-02T10:00:00+00:00",
        ),
    ]

    events = build_campaign_timeline(
        candidate,
        reports,
    )

    assert [
        event.investigation_id
        for event in events
    ] == [
        "INV-A",
        "INV-B",
        "INV-C",
    ]


def test_missing_report_is_neutral():
    candidate = CampaignCandidate(
        campaign_id="campaign-test",
        investigation_ids=[
            "INV-A",
            "INV-MISSING",
        ],
        relationships=[],
        shared_artifacts=[],
        correlation_score=0.6,
        strength="moderate",
    )

    events = build_campaign_timeline(
        candidate,
        [
            report(
                "INV-A",
                "2026-09-01T10:00:00+00:00",
            )
        ],
    )

    assert len(events) == 1
    assert (
        events[0].investigation_id
        == "INV-A"
    )
