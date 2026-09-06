from __future__ import annotations

from app.campaign_detection.artifacts import artifacts_from_report
from app.campaign_detection.engine import correlate_reports
from app.reports.models import IOC, InvestigationReport


def make_ioc(
    kind: str,
    value: str,
) -> IOC:
    return IOC(
        type=kind,
        value=value,
        source="test",
        confidence=1.0,
    )


def make_report(
    investigation_id: str,
    *,
    created_at: str,
    iocs: list[IOC],
) -> InvestigationReport:
    return InvestigationReport(
        investigation_id=investigation_id,
        created_at=created_at,
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
        iocs=iocs,
        timeline=[],
        recommendations=[],
        limitations=[],
        evidence={},
        analyst_model="mock",
        metadata={},
    )


def test_single_report_has_no_campaign():
    reports = [
        make_report(
            "INV-1",
            created_at="2026-09-01T10:00:00+00:00",
            iocs=[
                make_ioc(
                    "domain",
                    "evil.example",
                )
            ],
        )
    ]

    assert correlate_reports(reports) == []


def test_unrelated_reports_do_not_correlate():
    reports = [
        make_report(
            "INV-1",
            created_at="2026-09-01T10:00:00+00:00",
            iocs=[
                make_ioc(
                    "domain",
                    "one.example",
                )
            ],
        ),
        make_report(
            "INV-2",
            created_at="2026-09-01T11:00:00+00:00",
            iocs=[
                make_ioc(
                    "domain",
                    "two.example",
                )
            ],
        ),
    ]

    assert correlate_reports(reports) == []


def test_shared_domain_creates_campaign():
    reports = [
        make_report(
            "INV-1",
            created_at="2026-09-01T10:00:00+00:00",
            iocs=[
                make_ioc(
                    "domain",
                    "evil.example",
                )
            ],
        ),
        make_report(
            "INV-2",
            created_at="2026-09-01T11:00:00+00:00",
            iocs=[
                make_ioc(
                    "hostname",
                    "EVIL.EXAMPLE.",
                )
            ],
        ),
    ]

    campaigns = correlate_reports(reports)

    assert len(campaigns) == 1
    assert campaigns[0].correlation_score == 0.6
    assert campaigns[0].strength == "moderate"


def test_shared_ip_alone_is_not_enough():
    reports = [
        make_report(
            "INV-1",
            created_at="2026-09-01T10:00:00+00:00",
            iocs=[
                make_ioc(
                    "ip",
                    "203.0.113.10",
                )
            ],
        ),
        make_report(
            "INV-2",
            created_at="2026-09-01T11:00:00+00:00",
            iocs=[
                make_ioc(
                    "ip",
                    "203.0.113.10",
                )
            ],
        ),
    ]

    assert correlate_reports(reports) == []


def test_shared_sha256_is_strong():
    value = "a" * 64

    reports = [
        make_report(
            "INV-1",
            created_at="2026-09-01T10:00:00+00:00",
            iocs=[
                make_ioc(
                    "sha256",
                    value,
                )
            ],
        ),
        make_report(
            "INV-2",
            created_at="2026-09-01T11:00:00+00:00",
            iocs=[
                make_ioc(
                    "sha256",
                    value.upper(),
                )
            ],
        ),
    ]

    campaign = correlate_reports(
        reports
    )[0]

    assert campaign.correlation_score == 1.0
    assert campaign.strength == "strong"


def test_domain_and_ip_corroborate():
    reports = [
        make_report(
            "INV-1",
            created_at="2026-09-01T10:00:00+00:00",
            iocs=[
                make_ioc(
                    "domain",
                    "evil.example",
                ),
                make_ioc(
                    "ip",
                    "203.0.113.10",
                ),
            ],
        ),
        make_report(
            "INV-2",
            created_at="2026-09-01T11:00:00+00:00",
            iocs=[
                make_ioc(
                    "domain",
                    "evil.example",
                ),
                make_ioc(
                    "ip",
                    "203.0.113.10",
                ),
            ],
        ),
    ]

    campaign = correlate_reports(
        reports
    )[0]

    assert campaign.correlation_score == 0.78


def test_transitive_campaign_grouping():
    reports = [
        make_report(
            "INV-A",
            created_at="2026-09-01T10:00:00+00:00",
            iocs=[
                make_ioc(
                    "domain",
                    "alpha.example",
                )
            ],
        ),
        make_report(
            "INV-B",
            created_at="2026-09-01T11:00:00+00:00",
            iocs=[
                make_ioc(
                    "domain",
                    "alpha.example",
                ),
                make_ioc(
                    "email",
                    "actor@example.test",
                ),
            ],
        ),
        make_report(
            "INV-C",
            created_at="2026-09-01T12:00:00+00:00",
            iocs=[
                make_ioc(
                    "email",
                    "ACTOR@example.test",
                )
            ],
        ),
    ]

    campaigns = correlate_reports(reports)

    assert len(campaigns) == 1

    assert campaigns[0].investigation_ids == [
        "INV-A",
        "INV-B",
        "INV-C",
    ]


def test_campaign_id_is_deterministic():
    reports = [
        make_report(
            "INV-A",
            created_at="2026-09-01T10:00:00+00:00",
            iocs=[
                make_ioc(
                    "domain",
                    "evil.example",
                )
            ],
        ),
        make_report(
            "INV-B",
            created_at="2026-09-01T11:00:00+00:00",
            iocs=[
                make_ioc(
                    "domain",
                    "evil.example",
                )
            ],
        ),
    ]

    first = correlate_reports(
        reports
    )[0]

    second = correlate_reports(
        list(reversed(reports))
    )[0]

    assert (
        first.campaign_id
        ==
        second.campaign_id
    )


def test_campaign_timeline_bounds():
    reports = [
        make_report(
            "INV-1",
            created_at="2026-09-03T10:00:00+00:00",
            iocs=[
                make_ioc(
                    "domain",
                    "evil.example",
                )
            ],
        ),
        make_report(
            "INV-2",
            created_at="2026-09-01T10:00:00+00:00",
            iocs=[
                make_ioc(
                    "domain",
                    "evil.example",
                )
            ],
        ),
        make_report(
            "INV-3",
            created_at="2026-09-05T10:00:00+00:00",
            iocs=[
                make_ioc(
                    "domain",
                    "evil.example",
                )
            ],
        ),
    ]

    campaign = correlate_reports(
        reports
    )[0]

    assert campaign.first_seen == (
        "2026-09-01T10:00:00+00:00"
    )

    assert campaign.last_seen == (
        "2026-09-05T10:00:00+00:00"
    )


def test_hostname_normalizes_to_domain():
    report = make_report(
        "INV-1",
        created_at="2026-09-01T10:00:00+00:00",
        iocs=[
            make_ioc(
                "hostname",
                "Login.Evil.Example.",
            )
        ],
    )

    artifacts = artifacts_from_report(
        report
    )

    assert len(artifacts) == 1
    assert artifacts[0].type == "domain"
    assert (
        artifacts[0].value
        ==
        "login.evil.example"
    )


def test_security_boundary_metadata():
    reports = [
        make_report(
            "INV-1",
            created_at="2026-09-01T10:00:00+00:00",
            iocs=[
                make_ioc(
                    "domain",
                    "evil.example",
                )
            ],
        ),
        make_report(
            "INV-2",
            created_at="2026-09-01T11:00:00+00:00",
            iocs=[
                make_ioc(
                    "domain",
                    "evil.example",
                )
            ],
        ),
    ]

    campaign = correlate_reports(
        reports
    )[0]

    assert campaign.metadata[
        "deterministic"
    ] is True

    assert campaign.metadata[
        "ai_used"
    ] is False

    assert campaign.metadata[
        "external_lookup_used"
    ] is False

    assert campaign.metadata[
        "threat_actor_attributed"
    ] is False

    assert campaign.metadata[
        "shared_artifact_is_not_proof"
    ] is True
