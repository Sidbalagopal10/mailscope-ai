from __future__ import annotations

from app.global_entity_registry.identity.confidence_engine import (
    confidence_band,
    _independent_support_probability,
)


def test_probability_single_source():
    value = (
        _independent_support_probability(
            {
                "source_a": 0.80,
            }
        )
    )

    assert round(
        value,
        2,
    ) == 0.80


def test_probability_two_sources():
    value = (
        _independent_support_probability(
            {
                "source_a": 0.80,
                "source_b": 0.70,
            }
        )
    )

    assert round(
        value,
        2,
    ) == 0.94


def test_duplicate_source_not_possible_in_mapping():
    value = (
        _independent_support_probability(
            {
                "ror": 0.97,
            }
        )
    )

    assert round(
        value,
        2,
    ) == 0.97


def test_confidence_bands():
    assert (
        confidence_band(
            97
        )
        == "very_high"
    )

    assert (
        confidence_band(
            85
        )
        == "high"
    )

    assert (
        confidence_band(
            65
        )
        == "moderate"
    )

    assert (
        confidence_band(
            40
        )
        == "low"
    )

    assert (
        confidence_band(
            10
        )
        == "very_low"
    )
