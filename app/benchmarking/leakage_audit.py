from __future__ import annotations

from typing import Any

from app.benchmarking.urlhaus_index import (
    exact_lookup,
)


def audit_cross_feed_overlap(
    value: str,
) -> dict[str, Any]:
    """
    Check whether an OpenPhish holdout URL also appears
    in URLhaus.

    OpenPhish itself is NEVER queried by the detector.
    """
    urlhaus = exact_lookup(
        value
    )

    return {
        "urlhaus_exact_overlap": bool(
            urlhaus.get(
                "matched",
                False,
            )
            and urlhaus.get(
                "match_type"
            )
            == "exact_url"
        ),
        "urlhaus_match_type": (
            urlhaus.get(
                "match_type"
            )
        ),
    }
