from __future__ import annotations

from fastapi.testclient import (
    TestClient,
)

from app.main import app


client = TestClient(app)


def report(
    investigation_id: str,
    domain: str,
) -> dict:
    return {
        "investigation_id": (
            investigation_id
        ),
        "created_at": (
            "2026-09-05T12:00:00+00:00"
        ),
        "target": (
            f"https://{domain}/"
        ),
        "target_type": "url",
        "verdict": "suspicious",
        "confidence": 80.0,
        "severity": 6.0,
        "risk_level": "MODERATE",
        "executive_summary": "test",
        "findings": [],
        "identity": {},
        "mitre_attack": [],
        "iocs": [
            {
                "type": "domain",
                "value": domain,
                "source": "test",
                "confidence": 1.0,
            }
        ],
        "timeline": [],
        "recommendations": [],
        "limitations": [],
        "evidence": {},
        "analyst_model": "mock",
        "metadata": {},
    }


def test_campaign_correlation_endpoint():
    response = client.post(
        "/campaigns/correlate?persist=false",
        json={
            "reports": [
                report(
                    "API-INV-A",
                    "evil.example",
                ),
                report(
                    "API-INV-B",
                    "evil.example",
                ),
            ]
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload[
        "campaign_count"
    ] == 1

    assert payload[
        "metadata"
    ][
        "deterministic"
    ] is True

    assert payload[
        "metadata"
    ][
        "ai_used"
    ] is False

    assert payload[
        "metadata"
    ][
        "threat_actor_attributed"
    ] is False


def test_unrelated_reports_return_no_campaign():
    response = client.post(
        "/campaigns/correlate?persist=false",
        json={
            "reports": [
                report(
                    "API-INV-C",
                    "one.example",
                ),
                report(
                    "API-INV-D",
                    "two.example",
                ),
            ]
        },
    )

    assert response.status_code == 200

    assert response.json()[
        "campaign_count"
    ] == 0


def test_shared_ip_alone_does_not_create_campaign():
    first = report(
        "API-IP-A",
        "one.example",
    )

    second = report(
        "API-IP-B",
        "two.example",
    )

    first["iocs"] = [
        {
            "type": "ip",
            "value": "203.0.113.10",
            "source": "test",
            "confidence": 1.0,
        }
    ]

    second["iocs"] = [
        {
            "type": "ip",
            "value": "203.0.113.10",
            "source": "test",
            "confidence": 1.0,
        }
    ]

    response = client.post(
        "/campaigns/correlate?persist=false",
        json={
            "reports": [
                first,
                second,
            ]
        },
    )

    assert response.status_code == 200

    assert response.json()[
        "campaign_count"
    ] == 0


def test_unknown_campaign_returns_404():
    response = client.get(
        "/campaigns/"
        "campaign-does-not-exist"
    )

    assert response.status_code == 404


def test_campaign_list_endpoint():
    response = client.get(
        "/campaigns"
    )

    assert response.status_code == 200

    payload = response.json()

    assert "count" in payload
    assert "campaigns" in payload
