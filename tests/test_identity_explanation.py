from __future__ import annotations

from app.global_entity_registry.identity.explanation import (
    hostname_from_input,
)


def test_hostname_from_url():
    assert (
        hostname_from_input(
            "https://research.microsoft.com/test"
        )
        == "research.microsoft.com"
    )


def test_hostname_from_plain_domain():
    assert (
        hostname_from_input(
            "example.org"
        )
        == "example.org"
    )


def test_empty_hostname():
    assert (
        hostname_from_input(
            ""
        )
        == ""
    )
