from __future__ import annotations

from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urlsplit

from app.organization_graph.normalization import (
    normalize_organization_name,
)
from app.organization_graph.repository import (
    lookup_name,
)


def hostname_tokens(
    value: str,
) -> list[str]:
    cleaned = str(
        value or ""
    ).strip()

    if "://" not in cleaned:
        cleaned = (
            "https://"
            + cleaned
        )

    try:
        hostname = (
            urlsplit(
                cleaned
            ).hostname
            or ""
        )

    except ValueError:
        return []

    normalized = (
        normalize_organization_name(
            hostname.replace(
                ".",
                " ",
            ).replace(
                "-",
                " ",
            )
        )
    )

    return [
        token
        for token in normalized.split()
        if len(token) >= 3
    ]


def candidate_organizations(
    value: str,
) -> list[dict[str, Any]]:
    tokens = hostname_tokens(
        value
    )

    candidates: dict[
        int,
        dict[str, Any],
    ] = {}

    for token in tokens:
        for match in lookup_name(
            token,
            limit=20,
        ):
            node_id = int(
                match[
                    "node_id"
                ]
            )

            existing = candidates.get(
                node_id
            )

            if (
                existing is None
                or float(
                    match[
                        "confidence"
                    ]
                )
                > float(
                    existing[
                        "confidence"
                    ]
                )
            ):
                candidates[
                    node_id
                ] = {
                    **match,
                    "matched_token": token,
                }

    return list(
        candidates.values()
    )


def similarity(
    left: str,
    right: str,
) -> float:
    first = normalize_organization_name(
        left
    )

    second = normalize_organization_name(
        right
    )

    if not first or not second:
        return 0.0

    return round(
        SequenceMatcher(
            None,
            first,
            second,
        ).ratio(),
        4,
    )
