from __future__ import annotations

from app.domain_intelligence import (
    rdap_client,
)
from app.domain_intelligence.risk import (
    rdap_risk_evidence,
)


BOOTSTRAP = {
    "services": [
        [
            [
                "com",
                "net",
            ],
            [
                "https://rdap.example.test",
            ],
        ],
        [
            [
                "org",
            ],
            [
                "https://rdap-org.example.test/",
            ],
        ],
    ]
}


SAMPLE_RESPONSE = {
    "ldhName": "EXAMPLE.COM",
    "status": [
        "active",
    ],
    "events": [
        {
            "eventAction": "registration",
            "eventDate": (
                "2000-01-01T00:00:00Z"
            ),
        },
        {
            "eventAction": "expiration",
            "eventDate": (
                "2030-01-01T00:00:00Z"
            ),
        },
    ],
    "entities": [
        {
            "handle": "999",
            "roles": [
                "registrar",
            ],
            "vcardArray": [
                "vcard",
                [
                    [
                        "fn",
                        {},
                        "text",
                        "Example Registrar",
                    ]
                ],
            ],
        }
    ],
    "nameservers": [
        {
            "ldhName": "NS1.EXAMPLE.COM"
        },
        {
            "ldhName": "NS2.EXAMPLE.COM"
        },
    ],
    "secureDNS": {
        "delegationSigned": True
    },
}


def test_resolve_rdap_server():
    result = rdap_client.resolve_rdap_server(
        "www.example.com",
        bootstrap=BOOTSTRAP,
    )

    assert (
        result
        == "https://rdap.example.test"
    )


def test_analyze_rdap_payload():
    result = (
        rdap_client.analyze_rdap_payload(
            domain="example.com",
            rdap_server=(
                "https://rdap.example.test"
            ),
            payload=SAMPLE_RESPONSE,
        )
    )

    assert (
        result["domain"]
        == "example.com"
    )

    assert (
        result["registrar_name"]
        == "Example Registrar"
    )

    assert (
        result["dnssec_state"]
        == "signed"
    )

    assert (
        len(
            result["nameservers"]
        )
        == 2
    )

    assert (
        result["domain_age_days"]
        is not None
    )


def test_save_and_load_observation(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        rdap_client,
        "DATABASE_PATH",
        tmp_path / "domain.db",
    )

    result = (
        rdap_client.analyze_rdap_payload(
            domain="example.com",
            rdap_server=(
                "https://rdap.example.test"
            ),
            payload=SAMPLE_RESPONSE,
        )
    )

    saved = rdap_client.save_observation(
        result
    )

    loaded = rdap_client.get_observation(
        "example.com"
    )

    assert saved["domain"] == "example.com"
    assert loaded is not None
    assert loaded["dnssec_state"] == "signed"


def test_new_domain_is_weak_evidence_only():
    evidence = rdap_risk_evidence(
        {
            "lookup_status": "success",
            "domain_age_days": 2,
            "domain_status": [
                "active",
            ],
            "dnssec_state": "unsigned",
            "registrar_name": (
                "Example Registrar"
            ),
        }
    )

    assert (
        evidence["risk_adjustment"]
        <= 6
    )

    assert not evidence[
        "strong_signals"
    ]

    assert evidence[
        "weak_signals"
    ]


def test_old_domain_gets_small_positive_signal():
    evidence = rdap_risk_evidence(
        {
            "lookup_status": "success",
            "domain_age_days": 5000,
            "domain_status": [
                "active",
            ],
            "dnssec_state": "signed",
            "registrar_name": (
                "Example Registrar"
            ),
        }
    )

    assert (
        evidence["risk_adjustment"]
        < 0
    )
