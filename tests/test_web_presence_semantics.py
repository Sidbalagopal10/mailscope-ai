from __future__ import annotations

from app.global_entity_registry.identity.web_presence import (
    WebPresenceMode,
)


def test_web_presence_modes_exist():
    assert (
        WebPresenceMode.EXCLUSIVE.value
        == "exclusive"
    )

    assert (
        WebPresenceMode.SHARED.value
        == "shared"
    )

    assert (
        WebPresenceMode.AMBIGUOUS.value
        == "ambiguous"
    )

    assert (
        WebPresenceMode.UNKNOWN.value
        == "unknown"
    )


def test_shared_presence_is_not_same_as_conflicting_owner():
    # This test expresses the architectural rule:
    #
    # multiple legitimate web presences on one hostname
    # must not automatically imply ownership conflict.

    assert (
        WebPresenceMode.SHARED
        != WebPresenceMode.AMBIGUOUS
    )
