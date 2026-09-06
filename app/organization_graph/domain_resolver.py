from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from app.global_entity_registry.database import (
    connection,
)
from app.organization_graph.database import (
    initialize_graph_schema,
)


BLOCKED_RELATIONSHIP_TYPES = {
    "social_profile",
    "code_repository",
    "research_profile",
    "blog_profile",
    "user_generated_hosting",
    "shared_platform",
    "marketplace_profile",
}


def hostname_from_value(
    value: str,
) -> str:
    cleaned = str(
        value or ""
    ).strip()

    if not cleaned:
        return ""

    if "://" not in cleaned:
        cleaned = (
            "https://"
            + cleaned
        )

    try:
        return (
            urlsplit(
                cleaned
            ).hostname
            or ""
        ).lower().rstrip(".")

    except ValueError:
        return ""


def resolve_official_hostname(
    value: str,
) -> list[dict[str, Any]]:
    """
    Resolve exact official domains and true subdomains.

    Platform/profile relationships are excluded from
    official identity resolution.
    """

    initialize_graph_schema()

    hostname = hostname_from_value(
        value
    )

    if not hostname:
        return []

    with connection() as db:
        rows = db.execute(
            """
            SELECT
                n.id AS node_id,
                n.canonical_name,
                n.entity_type,
                n.country_code,

                d.domain,
                d.relationship_type,
                d.confidence,
                d.source_count,
                d.integrity_state,
                d.website_relationship_type,
                d.platform_provider,
                d.platform_suffix

            FROM organization_graph_domains d

            JOIN organization_graph_nodes n
              ON n.id = d.node_id

            WHERE n.active = 1

              AND COALESCE(
                    d.usable_for_identity,
                    1
                  ) = 1

              AND COALESCE(
                    d.website_relationship_type,
                    'official_website_candidate'
                  )
                  NOT IN (
                    'social_profile',
                    'code_repository',
                    'research_profile',
                    'blog_profile',
                    'user_generated_hosting',
                    'shared_platform',
                    'marketplace_profile'
                  )
            """
        ).fetchall()

    matches = []

    for row in rows:
        official = str(
            row[
                "domain"
            ]
        ).lower().rstrip(".")

        if hostname == official:
            relationship = "exact"

        elif hostname.endswith(
            "." + official
        ):
            relationship = (
                "true_subdomain"
            )

        else:
            continue

        matches.append(
            {
                **dict(row),

                "hostname": hostname,

                "domain_relationship": (
                    relationship
                ),
            }
        )

    matches.sort(
        key=lambda item: (
            len(
                item[
                    "domain"
                ]
            ),
            int(
                item[
                    "source_count"
                ]
                or 0
            ),
            float(
                item[
                    "confidence"
                ]
                or 0.0
            ),
        ),
        reverse=True,
    )

    return matches
