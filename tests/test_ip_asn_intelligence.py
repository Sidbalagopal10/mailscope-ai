from __future__ import annotations

from app.network_intelligence import (
    ip_asn_intelligence as intelligence,
)
from app.network_intelligence.risk import (
    ip_asn_risk_evidence,
)


def test_public_ip_validation():
    assert intelligence.is_public_ip(
        "8.8.8.8"
    )

    assert not intelligence.is_public_ip(
        "127.0.0.1"
    )

    assert not intelligence.is_public_ip(
        "192.168.1.1"
    )

    assert not intelligence.is_public_ip(
        "169.254.169.254"
    )


def test_ipv4_cymru_query_name():
    assert (
        intelligence.cymru_origin_query_name(
            "8.8.8.8"
        )
        == "8.8.8.8.origin.asn.cymru.com"
    )


def test_parse_origin_response():
    result = (
        intelligence.parse_origin_response(
            (
                "15169 | 8.8.8.0/24 | US | "
                "arin | 1992-12-01"
            )
        )
    )

    assert result[
        "asns"
    ] == [
        15169
    ]

    assert result[
        "prefix"
    ] == "8.8.8.0/24"

    assert result[
        "country_code"
    ] == "US"


def test_parse_asn_response():
    result = (
        intelligence.parse_asn_response(
            (
                "15169 | US | arin | "
                "2000-03-30 | GOOGLE, US"
            )
        )
    )

    assert result[
        "asn"
    ] == 15169

    assert "GOOGLE" in result[
        "network_name"
    ]


def test_save_and_load_observation(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        intelligence,
        "DATABASE_PATH",
        tmp_path / "network.db",
    )

    observation = {
        "hostname": "example.com",
        "lookup_status": "success",
        "ipv4_addresses": [
            "93.184.216.34"
        ],
        "ipv6_addresses": [],
        "public_addresses": [
            "93.184.216.34"
        ],
        "private_or_special_addresses": [],
        "asn_records": [
            {
                "ip_address": "93.184.216.34",
                "available": True,
                "asns": [
                    15133
                ],
                "prefix": "93.184.216.0/24",
                "country_code": "US",
                "registry": "arin",
                "allocated_date": "2008-06-02",
                "asn_details": [
                    {
                        "available": True,
                        "asn": 15133,
                        "network_name": (
                            "EDGECAST"
                        ),
                    }
                ],
            }
        ],
        "unique_asns": [
            15133
        ],
        "unique_network_names": [
            "EDGECAST"
        ],
        "reverse_dns": [],
        "error_messages": [],
        "observed_at": (
            "2026-08-04T00:00:00+00:00"
        ),
    }

    intelligence.save_observation(
        observation
    )

    loaded = intelligence.get_observation(
        "example.com"
    )

    assert loaded is not None

    assert loaded[
        "unique_asns"
    ] == [
        15133
    ]

    assert loaded[
        "unique_network_names"
    ] == [
        "EDGECAST"
    ]


def test_major_cloud_provider_is_neutral():
    evidence = ip_asn_risk_evidence(
        {
            "lookup_status": "success",
            "public_addresses": [
                "203.0.113.10"
            ],
            "unique_asns": [
                13335
            ],
            "unique_network_names": [
                "CLOUDFLARENET"
            ],
            "reverse_dns": [],
        }
    )

    assert evidence[
        "uses_major_shared_infrastructure"
    ]

    assert (
        evidence[
            "risk_adjustment"
        ]
        <= 0
    )


def test_missing_public_ip_is_bounded():
    evidence = ip_asn_risk_evidence(
        {
            "lookup_status": "limited",
            "public_addresses": [],
            "unique_asns": [],
            "unique_network_names": [],
            "reverse_dns": [],
        }
    )

    assert (
        evidence[
            "risk_adjustment"
        ]
        <= 4
    )
