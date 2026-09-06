from __future__ import annotations

from app.organization_graph.domain_resolver import (
    hostname_from_value,
)


def test_hostname_extraction():
    assert (
        hostname_from_value(
            "https://research.microsoft.com/"
        )
        == "research.microsoft.com"
    )


def test_deceptive_suffix_is_not_subdomain():
    hostname = "github.com.attacker.example"

    official = "github.com"

    assert not (
        hostname == official
        or hostname.endswith(
            "." + official
        )
    )
