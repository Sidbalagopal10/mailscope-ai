from __future__ import annotations

from app.rdap_intelligence.client import (
    event_date,
    parse_datetime,
)


def test_parse_rdap_datetime():
    result = parse_datetime(
        "2026-01-01T00:00:00Z"
    )

    assert result is not None

    assert (
        result.year
        == 2026
    )


def test_registration_event():
    payload = {
        "events": [
            {
                "eventAction": (
                    "registration"
                ),
                "eventDate": (
                    "2024-01-01T00:00:00Z"
                ),
            }
        ]
    }

    assert (
        event_date(
            payload,
            {
                "registration"
            },
        )
        == "2024-01-01T00:00:00Z"
    )
