from __future__ import annotations

from app.organization_graph.normalization import (
    normalize_organization_name,
    organization_core_name,
)


def test_normalization():
    assert (
        normalize_organization_name(
            "Microsoft Corporation"
        )
        == "microsoft corporation"
    )


def test_corporate_suffix_removed():
    assert (
        organization_core_name(
            "Microsoft Corporation"
        )
        == "microsoft"
    )


def test_unicode_normalization():
    result = normalize_organization_name(
        "Université Exemple"
    )

    assert (
        "universite"
        in result
    )
