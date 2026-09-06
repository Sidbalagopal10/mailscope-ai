from __future__ import annotations

from app.dns_intelligence import (
    dns_lookup,
)
from app.dns_intelligence.dns_risk import (
    dns_risk_evidence,
)


def test_normalize_domain():
    assert (
        dns_lookup.normalize_domain(
            "https://www.Example.COM/path"
        )
        == "example.com"
    )


def test_extract_spf_records():
    records = [
        {
            "text": (
                "v=spf1 include:_spf.example.com ~all"
            )
        },
        {
            "text": "normal verification text"
        },
    ]

    result = (
        dns_lookup.extract_spf_records(
            records
        )
    )

    assert len(result) == 1

    assert result[0].startswith(
        "v=spf1"
    )


def test_extract_dmarc_records():
    records = [
        {
            "text": (
                "v=DMARC1; p=reject; rua=mailto:test@example.com"
            )
        }
    ]

    result = (
        dns_lookup.extract_dmarc_records(
            records
        )
    )

    assert len(result) == 1


def test_save_and_load_observation(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        dns_lookup,
        "DATABASE_PATH",
        tmp_path / "dns.db",
    )

    observation = {
        "domain": "example.com",
        "registrable_domain": "example.com",
        "lookup_status": "success",
        "records": {
            "a": [
                {
                    "address": "93.184.216.34"
                }
            ],
            "aaaa": [],
            "mx": [
                {
                    "preference": 10,
                    "exchange": "mail.example.com",
                }
            ],
            "ns": [
                {
                    "target": "ns1.example.com"
                },
                {
                    "target": "ns2.example.com"
                },
            ],
            "txt": [
                {
                    "text": "v=spf1 -all"
                }
            ],
            "caa": [],
            "soa": [],
            "cname": [],
            "ds": [],
        },
        "spf_records": [
            "v=spf1 -all"
        ],
        "dmarc_records": [
            "v=DMARC1; p=reject"
        ],
        "has_a": True,
        "has_aaaa": False,
        "has_mx": True,
        "has_spf": True,
        "has_dmarc": True,
        "has_caa": False,
        "has_dnssec_delegation": False,
        "mx_count": 1,
        "ns_count": 2,
        "txt_count": 1,
        "minimum_ttl": 300,
        "maximum_ttl": 3600,
        "errors": [],
        "observed_at": (
            "2026-08-04T00:00:00+00:00"
        ),
    }

    saved = dns_lookup.save_observation(
        observation
    )

    loaded = dns_lookup.get_observation(
        "example.com"
    )

    assert saved[
        "domain"
    ] == "example.com"

    assert loaded is not None

    assert loaded[
        "has_spf"
    ]

    assert loaded[
        "dmarc_records"
    ]


def test_missing_mail_records_are_bounded():
    evidence = dns_risk_evidence(
        {
            "lookup_status": "success",
            "has_a": True,
            "has_aaaa": False,
            "has_mx": False,
            "has_spf": False,
            "has_dmarc": False,
            "has_caa": False,
            "has_dnssec_delegation": False,
            "mx_count": 0,
            "ns_count": 2,
        }
    )

    assert (
        evidence[
            "risk_adjustment"
        ]
        <= 3
    )


def test_mail_domain_without_spf_or_dmarc_adds_weak_risk():
    evidence = dns_risk_evidence(
        {
            "lookup_status": "success",
            "has_a": True,
            "has_aaaa": False,
            "has_mx": True,
            "has_spf": False,
            "has_dmarc": False,
            "has_caa": False,
            "has_dnssec_delegation": False,
            "mx_count": 1,
            "ns_count": 2,
        }
    )

    assert (
        evidence[
            "risk_adjustment"
        ]
        > 0
    )

    assert len(
        evidence[
            "weak_signals"
        ]
    ) >= 2


def test_strong_dns_configuration_reduces_uncertainty():
    evidence = dns_risk_evidence(
        {
            "lookup_status": "success",
            "has_a": True,
            "has_aaaa": True,
            "has_mx": True,
            "has_spf": True,
            "has_dmarc": True,
            "has_caa": True,
            "has_dnssec_delegation": True,
            "mx_count": 3,
            "ns_count": 4,
        }
    )

    assert (
        evidence[
            "risk_adjustment"
        ]
        <= 0
    )

    assert evidence[
        "positive_signals"
    ]
