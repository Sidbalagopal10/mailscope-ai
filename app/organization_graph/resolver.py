from __future__ import annotations

from difflib import SequenceMatcher
from typing import Any

from app.organization_graph.normalization import (
    normalize_organization_name,
    organization_core_name,
)
from app.organization_graph.repository import (
    organization_profile,
)
from app.organization_graph.search_index import (
    search_organizations,
)


REGIONAL_TERMS = {
    "united",
    "states",
    "kingdom",
    "usa",
    "us",
    "uk",
    "india",
    "canada",
    "australia",
    "germany",
    "france",
    "italy",
    "israel",
    "finland",
    "belgium",
    "norway",
    "portugal",
    "ireland",
    "switzerland",
    "singapore",
    "netherlands",
}


def similarity(
    first: str,
    second: str,
) -> float:
    left = normalize_organization_name(
        first
    )

    right = normalize_organization_name(
        second
    )

    if not left or not right:
        return 0.0

    if left == right:
        return 1.0

    return round(
        SequenceMatcher(
            None,
            left,
            right,
        ).ratio(),
        4,
    )


def reduced_brand_name(
    value: str,
) -> str:
    core = organization_core_name(
        value
    )

    tokens = [
        token
        for token in core.split()
        if token not in REGIONAL_TERMS
    ]

    return " ".join(
        tokens
    )


def candidate_similarity(
    brand_text: str,
    match: dict[str, Any],
) -> float:
    """
    Use every identity representation we actually possess.

    The FTS matched alias is often more useful than the
    regional canonical entity name.
    """

    representations = {
        str(
            match.get(
                "canonical_name",
                "",
            )
        ),
        str(
            match.get(
                "matched_name",
                "",
            )
        ),
        str(
            match.get(
                "core_name",
                "",
            )
        ),
    }

    expanded = set()

    for representation in representations:
        if not representation:
            continue

        expanded.add(
            representation
        )

        expanded.add(
            organization_core_name(
                representation
            )
        )

        expanded.add(
            reduced_brand_name(
                representation
            )
        )

    brand_forms = {
        brand_text,
        organization_core_name(
            brand_text
        ),
        reduced_brand_name(
            brand_text
        ),
    }

    scores = []

    for first in brand_forms:
        for second in expanded:
            if first and second:
                scores.append(
                    similarity(
                        first,
                        second,
                    )
                )

    return max(
        scores,
        default=0.0,
    )


def domain_belongs_to_profile(
    hostname: str,
    profile: dict[str, Any],
) -> dict[str, Any]:
    domains = profile.get(
        "domains",
        []
    )

    for item in domains:
        official = str(
            item[
                "domain"
            ]
        ).lower().rstrip(".")

        if hostname == official:
            return {
                "belongs": True,
                "relationship": "exact",
                "official_domain": official,
            }

        if hostname.endswith(
            "." + official
        ):
            return {
                "belongs": True,
                "relationship": "true_subdomain",
                "official_domain": official,
            }

    return {
        "belongs": False,
        "relationship": "none",
        "official_domain": None,
    }


def resolve_brand_reference(
    *,
    value: str,
    hostname: str,
    brand_text: str,
    limit: int = 30,
) -> list[dict[str, Any]]:
    matches = search_organizations(
        brand_text,
        limit=limit,
    )

    results = []

    for match in matches:
        profile = organization_profile(
            int(
                match[
                    "node_id"
                ]
            )
        )

        if not profile:
            continue

        ownership = domain_belongs_to_profile(
            hostname,
            profile,
        )

        score = candidate_similarity(
            brand_text,
            match,
        )

        results.append(
            {
                "node_id": int(
                    match[
                        "node_id"
                    ]
                ),

                "canonical_name": (
                    match[
                        "canonical_name"
                    ]
                ),

                "entity_type": (
                    match[
                        "entity_type"
                    ]
                ),

                "country_code": (
                    match[
                        "country_code"
                    ]
                ),

                "matched_name": (
                    match[
                        "matched_name"
                    ]
                ),

                "matched_name_type": (
                    match[
                        "name_type"
                    ]
                ),

                "brand_similarity": (
                    score
                ),

                "domain_belongs_to_organization": (
                    ownership[
                        "belongs"
                    ]
                ),

                "domain_relationship": (
                    ownership[
                        "relationship"
                    ]
                ),

                "official_domain": (
                    ownership[
                        "official_domain"
                    ]
                ),
            }
        )

    results.sort(
        key=lambda item: (
            item[
                "domain_belongs_to_organization"
            ],
            item[
                "brand_similarity"
            ],
        ),
        reverse=True,
    )

    return results
