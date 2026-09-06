from __future__ import annotations

from typing import Any

from app.organization_graph.search_index import (
    search_organizations,
)


def organization_coverage(
    name: str,
) -> dict[str, Any]:
    matches = search_organizations(
        name,
        limit=20,
    )

    return {
        "query": name,
        "covered": bool(
            matches
        ),
        "candidate_count": len(
            matches
        ),
        "candidates": matches,
    }


def coverage_report(
    names: list[str],
) -> dict[str, Any]:
    results = [
        organization_coverage(
            name
        )
        for name in names
    ]

    covered = sum(
        bool(
            item[
                "covered"
            ]
        )
        for item in results
    )

    return {
        "queries": len(
            results
        ),

        "covered": covered,

        "missing": (
            len(results)
            - covered
        ),

        "coverage_rate": (
            round(
                covered
                / len(
                    results
                ),
                4,
            )
            if results
            else 0.0
        ),

        "results": results,
    }
