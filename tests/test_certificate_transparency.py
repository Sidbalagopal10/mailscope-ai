from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.domain_intelligence import (
    certificate_transparency as ct,
)
from app.domain_intelligence.ct_risk import (
    certificate_transparency_evidence,
)


SAMPLE_RESULTS = [
    {
        "issuer_ca_id": 100,
        "issuer_name": (
            "C=US, O=Example CA, CN=Example CA"
        ),
        "common_name": "example.org",
        "name_value": (
            "example.org\n"
            "www.example.org\n"
            "*.example.org"
        ),
        "id": 123,
        "entry_timestamp": (
            "2020-01-01T00:00:00"
        ),
        "not_before": (
            "2019-12-31T00:00:00"
        ),
        "not_after": (
            "2020-03-31T00:00:00"
        ),
        "serial_number": "ABC123",
    },
    {
        "issuer_ca_id": 101,
        "issuer_name": (
            "C=US, O=New CA, CN=New CA"
        ),
        "common_name": "www.example.org",
        "name_value": (
            "www.example.org"
        ),
        "id": 456,
        "entry_timestamp": (
            "2025-01-01T00:00:00"
        ),
        "not_before": (
            "2024-12-31T00:00:00"
        ),
        "not_after": (
            "2025-03-31T00:00:00"
        ),
        "serial_number": "DEF456",
    },
]


def test_build_query_url():
    result = ct.build_query_url(
        "www.example.org",
        include_subdomains=True,
    )

    assert "output=json" in result
    assert "example.org" in result


def test_summarize_results():
    result = ct.summarize_results(
        domain="example.org",
        results=SAMPLE_RESULTS,
    )

    assert result[
        "lookup_status"
    ] == "success"

    assert result[
        "certificate_count"
    ] == 2

    assert (
        "www.example.org"
        in result["names"]
    )

    assert result[
        "newest_issuer_name"
    ] is not None


def test_unrelated_names_are_filtered():
    result = ct.summarize_results(
        domain="example.org",
        results=[
            {
                "id": 1,
                "serial_number": "1",
                "common_name": "evil.example.com",
                "name_value": "evil.example.com",
                "entry_timestamp": (
                    "2025-01-01T00:00:00"
                ),
            }
        ],
    )

    assert result[
        "certificate_count"
    ] == 0


def test_save_and_load(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        ct,
        "DATABASE_PATH",
        tmp_path / "ct.db",
    )

    summary = ct.summarize_results(
        domain="example.org",
        results=SAMPLE_RESULTS,
    )

    saved = ct.save_lookup(
        summary
    )

    loaded = ct.get_summary_for_domain(
        "www.example.org"
    )

    assert saved[
        "domain"
    ] == "example.org"

    assert loaded is not None

    assert loaded[
        "certificate_count"
    ] == 2


def test_new_certificate_history_is_weak_only():
    now = datetime.now(
        timezone.utc
    )

    evidence = (
        certificate_transparency_evidence(
            {
                "lookup_status": "success",
                "certificate_count": 1,
                "first_seen": (
                    now
                    - timedelta(
                        days=2
                    )
                ).isoformat(),
                "last_seen": now.isoformat(),
            }
        )
    )

    assert (
        evidence[
            "risk_adjustment"
        ]
        <= 2
    )

    assert evidence[
        "weak_signals"
    ]
