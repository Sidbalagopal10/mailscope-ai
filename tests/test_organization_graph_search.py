from __future__ import annotations

from app.organization_graph.normalization import (
    organization_core_name,
)
from app.organization_graph.resolver import (
    similarity,
)


def test_microsoft_core_name():
    assert (
        organization_core_name(
            "Microsoft Corporation"
        )
        == "microsoft"
    )


def test_core_similarity():
    result = similarity(
        "Microsoft",
        "Microsoft",
    )

    assert result == 1.0


def test_unrelated_names_low_similarity():
    result = similarity(
        "Microsoft",
        "University of Hawaii",
    )

    assert result < 0.5
