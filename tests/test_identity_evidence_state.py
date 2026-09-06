from __future__ import annotations

from app.global_entity_registry.identity.evidence_state import (
    IdentityEvidenceState,
)


def test_state_values():
    assert (
        IdentityEvidenceState.VERIFIED.value
        == "verified"
    )

    assert (
        IdentityEvidenceState.SUPPORTED.value
        == "supported"
    )

    assert (
        IdentityEvidenceState.CONFLICTING.value
        == "conflicting"
    )

    assert (
        IdentityEvidenceState.UNKNOWN.value
        == "unknown"
    )
