from __future__ import annotations

from app.global_entity_registry.identity.live_detector_adapter import (
    _read,
)


class Example:
    severity = 3.0
    risk_level = "LOW"


def test_read_object_attribute():
    assert (
        _read(
            Example(),
            "severity",
        )
        == 3.0
    )


def test_read_dictionary():
    assert (
        _read(
            {
                "severity": 5,
            },
            "severity",
        )
        == 5
    )


def test_missing_value():
    assert (
        _read(
            {},
            "missing",
            "fallback",
        )
        == "fallback"
    )
