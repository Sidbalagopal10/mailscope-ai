from __future__ import annotations

from app.global_entity_registry.source_agreement import (
    CONFLICTING,
    SUPPORTED,
    UNKNOWN,
    VERIFIED,
    decide_identity_state,
)


def test_two_sources_are_verified():
    result = decide_identity_state(
        domain_source_count=2,
        authoritative_domain_sources=1,
        high_confidence_legal_candidates=0,
        distinct_owners=1,
        strongest_domain_confidence=0.97,
    )

    assert (
        result[
            "identity_state"
        ]
        == VERIFIED
    )


def test_one_source_is_supported():
    result = decide_identity_state(
        domain_source_count=1,
        authoritative_domain_sources=0,
        high_confidence_legal_candidates=0,
        distinct_owners=1,
        strongest_domain_confidence=0.82,
    )

    assert (
        result[
            "identity_state"
        ]
        == SUPPORTED
    )


def test_unknown_is_neutral_identity():
    result = decide_identity_state(
        domain_source_count=0,
        authoritative_domain_sources=0,
        high_confidence_legal_candidates=0,
        distinct_owners=0,
        strongest_domain_confidence=0.0,
    )

    assert (
        result[
            "identity_state"
        ]
        == UNKNOWN
    )


def test_authoritative_plus_legal_is_verified():
    result = decide_identity_state(
        domain_source_count=1,
        authoritative_domain_sources=1,
        high_confidence_legal_candidates=1,
        distinct_owners=1,
        strongest_domain_confidence=0.97,
    )

    assert (
        result[
            "identity_state"
        ]
        == VERIFIED
    )


def test_conflicting_owner_overrides_everything():
    result = decide_identity_state(
        domain_source_count=4,
        authoritative_domain_sources=2,
        high_confidence_legal_candidates=3,
        distinct_owners=2,
        strongest_domain_confidence=0.99,
    )

    assert (
        result[
            "identity_state"
        ]
        == CONFLICTING
    )
