from __future__ import annotations

from app.threat_intelligence import (
    threatfox_client,
)
from app.threat_intelligence.threatfox_risk import (
    threatfox_risk_evidence,
)


def test_normalize_domain_indicator():
    result = (
        threatfox_client.normalize_indicator(
            "Example.COM"
        )
    )

    assert result[
        "indicator"
    ] == "example.com"

    assert result[
        "indicator_type"
    ] == "domain"


def test_normalize_url_indicator():
    result = (
        threatfox_client.normalize_indicator(
            "https://example.com/login"
        )
    )

    assert result[
        "indicator_type"
    ] == "url"

    assert result[
        "hostname"
    ] == "example.com"


def test_summarize_matched_response():
    result = (
        threatfox_client.summarize_response(
            indicator_data={
                "indicator": "evil.example",
                "indicator_type": "domain",
                "hostname": "evil.example",
            },
            response={
                "query_status": "ok",
                "data": [
                    {
                        "id": "1",
                        "ioc": "evil.example",
                        "ioc_type": "domain",
                        "threat_type": "botnet_cc",
                        "malware": "win.test",
                        "malware_printable": "Test Malware",
                        "confidence_level": 90,
                        "tags": [
                            "exe"
                        ],
                    }
                ],
            },
        )
    )

    assert result[
        "matched"
    ]

    assert result[
        "match_count"
    ] == 1

    assert result[
        "maximum_confidence"
    ] == 90

    assert result[
        "malware_families"
    ] == [
        "Test Malware"
    ]


def test_matched_ioc_is_strong_evidence():
    evidence = threatfox_risk_evidence(
        {
            "lookup_status": "success",
            "matched": True,
            "match_count": 2,
            "maximum_confidence": 90,
            "malware_families": [
                "Test Malware"
            ],
            "threat_types": [
                "botnet_cc"
            ],
        }
    )

    assert evidence[
        "matched"
    ]

    assert evidence[
        "risk_adjustment"
    ] >= 50

    assert evidence[
        "strong_signals"
    ]


def test_no_match_is_neutral():
    evidence = threatfox_risk_evidence(
        {
            "lookup_status": "success",
            "matched": False,
            "match_count": 0,
            "maximum_confidence": 0,
            "malware_families": [],
            "threat_types": [],
        }
    )

    assert (
        evidence[
            "risk_adjustment"
        ]
        == 0
    )


def test_save_and_load(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        threatfox_client,
        "DATABASE_PATH",
        tmp_path / "threatfox.db",
    )

    observation = {
        "indicator": "evil.example",
        "indicator_type": "domain",
        "hostname": "evil.example",
        "lookup_status": "success",
        "query_status": "ok",
        "matched": True,
        "match_count": 1,
        "matches": [
            {
                "ioc": "evil.example",
                "confidence_level": 90,
            }
        ],
        "malware_families": [
            "Test Malware"
        ],
        "threat_types": [
            "botnet_cc"
        ],
        "maximum_confidence": 90,
        "error_message": None,
        "observed_at": (
            "2026-08-04T00:00:00+00:00"
        ),
    }

    threatfox_client.save_observation(
        observation
    )

    loaded = (
        threatfox_client.get_observation(
            "evil.example"
        )
    )

    assert loaded is not None

    assert loaded[
        "matched"
    ]

    assert loaded[
        "malware_families"
    ] == [
        "Test Malware"
    ]
