from __future__ import annotations

from unittest.mock import patch

from app.analyst.evidence_builder import (
    build_url_evidence,
)
from app.threat_enrichment.models import (
    EnrichmentSource,
    ThreatEnrichment,
)


def fake_core() -> dict:
    return {
        "url": "https://example.com/",
        "severity": 0.0,
        "risk_level": "LOW",
        "is_suspicious": False,
        "reasons": [],
    }


def fake_identity() -> dict:
    return {
        "identity_known": False,
        "best_match": None,
        "matches": [],
    }


def fake_enrichment() -> ThreatEnrichment:
    return ThreatEnrichment(
        target="https://example.com/",
        hostname="example.com",
        created_at=(
            "2026-09-05T00:00:00+00:00"
        ),
        sources=[
            EnrichmentSource(
                source="dns",
                status="available",
                summary=(
                    "DNS intelligence collected."
                ),
                evidence={
                    "addresses": [
                        "203.0.113.10"
                    ]
                },
            ),
            EnrichmentSource(
                source="threatfox",
                status="available",
                summary=(
                    "ThreatFox intelligence collected."
                ),
                evidence={
                    "matched": False,
                    "relevant_exact_match": False,
                },
            ),
        ],
        metadata={
            "orchestrator_version": "2.0.0",
            "core_engine_modified": False,
            "ai_used": False,
            "threat_intelligence_is_evidence": True,
        },
    )


@patch(
    "app.analyst.evidence_builder._core_evidence"
)
@patch(
    "app.analyst.evidence_builder._identity_evidence"
)
@patch(
    "app.analyst.evidence_builder.enrich_target"
)
def test_threat_intelligence_enters_evidence(
    mock_enrich,
    mock_identity,
    mock_core,
):
    mock_core.return_value = fake_core()
    mock_identity.return_value = fake_identity()
    mock_enrich.return_value = fake_enrichment()

    evidence = build_url_evidence(
        "https://example.com/"
    )

    assert evidence.intelligence[
        "summary"
    ]["source_count"] == 2

    assert evidence.intelligence[
        "summary"
    ]["available_sources"] == 2

    names = [
        source["source"]
        for source
        in evidence.intelligence["sources"]
    ]

    assert "dns" in names
    assert "threatfox" in names


@patch(
    "app.analyst.evidence_builder._core_evidence"
)
@patch(
    "app.analyst.evidence_builder._identity_evidence"
)
@patch(
    "app.analyst.evidence_builder.enrich_target"
)
def test_threat_enrichment_does_not_modify_core(
    mock_enrich,
    mock_identity,
    mock_core,
):
    original_core = {
        "url": "https://example.com/",
        "severity": 0.0,
        "risk_level": "LOW",
        "is_suspicious": False,
        "reasons": [],
    }

    mock_core.return_value = dict(
        original_core
    )

    mock_identity.return_value = fake_identity()
    mock_enrich.return_value = fake_enrichment()

    evidence = build_url_evidence(
        "https://example.com/"
    )

    assert evidence.core == original_core

    assert evidence.core[
        "severity"
    ] == 0.0

    assert evidence.core[
        "risk_level"
    ] == "LOW"

    assert (
        evidence.metadata[
            "threat_intelligence_affects_core"
        ]
        is False
    )


@patch(
    "app.analyst.evidence_builder._core_evidence"
)
@patch(
    "app.analyst.evidence_builder._identity_evidence"
)
@patch(
    "app.analyst.evidence_builder.enrich_target"
)
def test_enrichment_failure_is_neutral(
    mock_enrich,
    mock_identity,
    mock_core,
):
    mock_core.return_value = fake_core()
    mock_identity.return_value = fake_identity()

    mock_enrich.side_effect = RuntimeError(
        "provider unavailable"
    )

    evidence = build_url_evidence(
        "https://example.com/"
    )

    assert evidence.core[
        "severity"
    ] == 0.0

    assert evidence.core[
        "risk_level"
    ] == "LOW"

    assert evidence.intelligence[
        "summary"
    ]["available_sources"] == 0

    assert evidence.intelligence[
        "summary"
    ]["failed_sources"] == 1

    assert (
        evidence.intelligence[
            "metadata"
        ][
            "provider_failure_is_neutral"
        ]
        is True
    )

    assert (
        "RuntimeError"
        in evidence.intelligence["error"]
    )


@patch(
    "app.analyst.evidence_builder._core_evidence"
)
@patch(
    "app.analyst.evidence_builder._identity_evidence"
)
@patch(
    "app.analyst.evidence_builder.enrich_target"
)
def test_threat_intelligence_has_no_independent_verdict(
    mock_enrich,
    mock_identity,
    mock_core,
):
    mock_core.return_value = fake_core()
    mock_identity.return_value = fake_identity()
    mock_enrich.return_value = fake_enrichment()

    evidence = build_url_evidence(
        "https://example.com/"
    )

    intelligence = (
        evidence.intelligence
    )

    assert "verdict" not in intelligence
    assert "severity" not in intelligence
    assert "risk_level" not in intelligence
