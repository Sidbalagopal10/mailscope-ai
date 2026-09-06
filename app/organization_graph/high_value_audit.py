from __future__ import annotations

from typing import Any

from app.global_entity_registry.database import connection
from app.organization_graph.coverage import (
    organization_coverage,
)


HIGH_VALUE_ORGANIZATIONS = [
    ("Microsoft", "microsoft.com"),
    ("Google", "google.com"),
    ("NVIDIA", "nvidia.com"),
    ("Apple", "apple.com"),
    ("GitHub", "github.com"),
    ("Amazon", "amazon.com"),
    ("Meta", "meta.com"),
    ("Netflix", "netflix.com"),
    ("PayPal", "paypal.com"),
    ("Cloudflare", "cloudflare.com"),
    ("OpenAI", "openai.com"),
    (
        "Indian Space Research Organisation",
        "isro.gov.in",
    ),
    (
        "George Washington University",
        "gwu.edu",
    ),
]


def audit() -> list[dict[str, Any]]:
    results = []

    with connection() as db:
        for name, domain in (
            HIGH_VALUE_ORGANIZATIONS
        ):
            coverage = organization_coverage(
                name
            )

            claims = db.execute(
                """
                SELECT
                    n.canonical_name,
                    n.entity_type,
                    n.country_code,
                    d.domain,
                    d.source_count,
                    d.integrity_state,
                    d.usable_for_identity

                FROM organization_graph_domains d

                JOIN organization_graph_nodes n
                  ON n.id = d.node_id

                WHERE d.domain = ?
                   OR ? LIKE '%.' || d.domain

                ORDER BY
                    d.source_count DESC,
                    d.confidence DESC
                """,
                (
                    domain,
                    domain,
                ),
            ).fetchall()

            results.append(
                {
                    "organization": name,
                    "expected_domain": domain,
                    "name_covered": (
                        coverage[
                            "covered"
                        ]
                    ),
                    "domain_claims": [
                        dict(row)
                        for row in claims
                    ],
                }
            )

    return results
