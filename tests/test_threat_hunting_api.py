from fastapi.testclient import (
    TestClient,
)

from app.main import app


client = TestClient(
    app
)


def test_hunt_requires_query():
    response = client.get(
        "/threat-hunts/search"
    )

    assert (
        response.status_code
        == 422
    )


def test_hunt_rejects_bad_type():
    response = client.get(
        "/threat-hunts/search",
        params={
            "query": "example.com",
            "observable_type": (
                "banana"
            ),
        },
    )

    assert (
        response.status_code
        == 400
    )


def test_hunt_endpoint_returns_security_metadata():
    response = client.get(
        "/threat-hunts/search",
        params={
            "query": (
                "definitely-not-present.example"
            ),
            "observable_type": (
                "domain"
            ),
        },
    )

    assert (
        response.status_code
        == 200
    )

    data = response.json()

    assert (
        data["metadata"][
            "deterministic"
        ]
        is True
    )

    assert (
        data["metadata"][
            "ai_used"
        ]
        is False
    )

    assert (
        data["metadata"][
            "verdict_modified"
        ]
        is False
    )
