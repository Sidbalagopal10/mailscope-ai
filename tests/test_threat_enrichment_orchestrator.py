from __future__ import annotations

from app.threat_enrichment.models import (
    EnrichmentSource,
    ThreatEnrichment,
)
from app.threat_enrichment.normalizers import (
    extract_hostname,
    normalize_profile_source,
)


def test_extract_hostname_from_url():
    assert (
        extract_hostname(
            "https://Example.COM/login"
        )
        == "example.com"
    )


def test_extract_hostname_from_domain():
    assert (
        extract_hostname(
            "example.com"
        )
        == "example.com"
    )


def test_empty_source_is_neutral_unavailable():
    result = normalize_profile_source(
        source="dns",
        payload={},
    )

    assert (
        result.status
        == "unavailable"
    )

    assert (
        result.error
        is None
    )


def test_provider_error_is_preserved():
    result = normalize_profile_source(
        source="rdap",
        payload={
            "error": "timeout",
        },
    )

    assert result.status == "error"
    assert result.error == "timeout"


def test_confidence_is_clamped():
    source = EnrichmentSource(
        source="test",
        status="available",
        summary="test",
        confidence=4.5,
    )

    assert (
        source.confidence
        == 1.0
    )


def test_enrichment_summary():
    enrichment = ThreatEnrichment(
        target=(
            "https://example.com"
        ),
        hostname="example.com",
        created_at=(
            "2026-09-01T00:00:00+00:00"
        ),
        sources=[
            EnrichmentSource(
                source="dns",
                status="available",
                summary="ok",
            ),

            EnrichmentSource(
                source="rdap",
                status="error",
                summary="failed",
                error="timeout",
            ),

            EnrichmentSource(
                source="threatfox",
                status="unavailable",
                summary="none",
            ),
        ],
    )

    payload = enrichment.to_dict()

    assert (
        payload["summary"][
            "source_count"
        ]
        == 3
    )

    assert (
        payload["summary"][
            "available_sources"
        ]
        == 1
    )

    assert (
        payload["summary"][
            "failed_sources"
        ]
        == 1
    )


def test_threat_intelligence_has_no_verdict_field():
    enrichment = ThreatEnrichment(
        target=(
            "https://example.com"
        ),
        hostname="example.com",
        created_at=(
            "2026-09-01T00:00:00+00:00"
        ),
    )

    payload = enrichment.to_dict()

    assert "verdict" not in payload
    assert "severity" not in payload
    assert "risk_level" not in payload
