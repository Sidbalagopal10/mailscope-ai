from __future__ import annotations

import base64

from app.threat_intelligence import (
    virustotal_client,
)
from app.threat_intelligence.virustotal_risk import (
    combine_virustotal_evidence,
    virustotal_risk_evidence,
)


def test_normalize_domain():
    result = (
        virustotal_client.normalize_indicator(
            "Example.COM"
        )
    )

    assert result[
        "indicator"
    ] == "example.com"

    assert result[
        "indicator_type"
    ] == "domain"


def test_normalize_url_removes_fragment():
    result = (
        virustotal_client.normalize_indicator(
            "HTTPS://Example.COM/login#section"
        )
    )

    assert result[
        "indicator"
    ] == "https://example.com/login"

    assert result[
        "indicator_type"
    ] == "url"


def test_url_identifier_is_unpadded_base64():
    normalized = (
        "https://example.com/login"
    )

    expected = base64.urlsafe_b64encode(
        normalized.encode(
            "utf-8"
        )
    ).decode(
        "ascii"
    ).rstrip("=")

    assert (
        virustotal_client.url_identifier(
            normalized
        )
        == expected
    )


def test_summarize_payload():
    result = (
        virustotal_client.summarize_payload(
            indicator_data={
                "indicator": "evil.example",
                "indicator_type": "domain",
                "hostname": "evil.example",
            },
            payload={
                "data": {
                    "id": "evil.example",
                    "type": "domain",
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 8,
                            "suspicious": 2,
                            "harmless": 20,
                            "undetected": 50,
                            "timeout": 1,
                        },
                        "reputation": -10,
                        "categories": {
                            "vendor": "phishing"
                        },
                        "tags": [
                            "malware"
                        ],
                    },
                }
            },
        )
    )

    assert result[
        "malicious"
    ] == 8

    assert result[
        "suspicious"
    ] == 2

    assert result[
        "total_engines"
    ] == 81

    assert result[
        "categories"
    ] == [
        "phishing"
    ]


def test_multiple_malicious_engines_are_strong():
    evidence = (
        virustotal_risk_evidence(
            {
                "lookup_status": "success",
                "object_found": True,
                "malicious": 8,
                "suspicious": 1,
                "harmless": 20,
                "total_engines": 80,
                "categories": [
                    "phishing"
                ],
            }
        )
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


def test_single_detection_is_bounded():
    evidence = (
        virustotal_risk_evidence(
            {
                "lookup_status": "success",
                "object_found": True,
                "malicious": 1,
                "suspicious": 0,
                "harmless": 50,
                "total_engines": 80,
                "categories": [],
            }
        )
    )

    assert evidence[
        "matched"
    ]

    assert (
        evidence[
            "risk_adjustment"
        ]
        < 35
    )


def test_no_detection_does_not_prove_safety():
    evidence = (
        virustotal_risk_evidence(
            {
                "lookup_status": "success",
                "object_found": True,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 60,
                "total_engines": 80,
                "categories": [],
            }
        )
    )

    assert not evidence[
        "matched"
    ]

    assert (
        evidence[
            "risk_adjustment"
        ]
        == 0
    )


def test_missing_report_is_neutral():
    evidence = (
        virustotal_risk_evidence(
            {
                "lookup_status": "success",
                "object_found": False,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "total_engines": 0,
                "categories": [],
            }
        )
    )

    assert not evidence[
        "matched"
    ]

    assert (
        evidence[
            "risk_adjustment"
        ]
        == 0
    )


def test_api_failure_is_neutral():
    evidence = (
        virustotal_risk_evidence(
            {
                "lookup_status": "failed",
                "object_found": False,
                "error_message": (
                    "Quota exceeded"
                ),
            }
        )
    )

    assert not evidence[
        "available"
    ]

    assert (
        evidence[
            "risk_adjustment"
        ]
        == 0
    )


def test_combined_uses_stronger_result():
    result = combine_virustotal_evidence(
        {
            "url_result": {
                "lookup_status": "success",
                "object_found": True,
                "malicious": 6,
                "suspicious": 0,
                "harmless": 20,
                "total_engines": 80,
                "categories": [],
            },
            "domain_result": {
                "lookup_status": "success",
                "object_found": True,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 60,
                "total_engines": 80,
                "categories": [],
            },
        }
    )

    assert result[
        "matched"
    ]

    assert (
        result[
            "risk_adjustment"
        ]
        >= 50
    )


def test_save_and_load(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        virustotal_client,
        "DATABASE_PATH",
        tmp_path / "virustotal.db",
    )

    observation = {
        "indicator": "example.org",
        "indicator_type": "domain",
        "hostname": "example.org",
        "lookup_status": "success",
        "object_found": True,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 70,
        "undetected": 10,
        "timeout_count": 0,
        "failure": 0,
        "total_engines": 80,
        "malicious_ratio": 0.0,
        "reputation": 5,
        "categories": [],
        "tags": [],
        "last_analysis_date": None,
        "raw_summary": {},
        "error_message": None,
        "observed_at": (
            "2026-08-05T00:00:00+00:00"
        ),
    }

    saved = (
        virustotal_client.save_observation(
            observation
        )
    )

    assert saved[
        "indicator"
    ] == "example.org"

    loaded = (
        virustotal_client.get_cached_observation(
            "domain",
            "example.org",
        )
    )

    assert loaded is not None
    assert loaded[
        "harmless"
    ] == 70
