from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.global_entity_registry.database import (
    connection,
)
from app.global_entity_registry.reconciliation.domain_relationship import (
    classify_domain_relationship,
)


def linked_wikidata_entities() -> list[dict[str, Any]]:
    with connection() as db:
        rows = db.execute(
            """
            SELECT DISTINCT
                e.id AS entity_id,
                e.canonical_name

            FROM entities e

            JOIN external_identifiers x
              ON x.entity_id = e.id

            WHERE LOWER(
                x.identifier_type
            ) = 'wikidata'

            ORDER BY e.canonical_name
            """
        ).fetchall()

    return [
        dict(
            row
        )
        for row in rows
    ]


def evidence_domains_for_entity(
    entity_id: int,
) -> dict[str, set[str]]:
    with connection() as db:
        rows = db.execute(
            """
            SELECT
                d.domain,
                es.source_name

            FROM domains d

            JOIN evidence_sources es
              ON es.domain_id = d.id

            WHERE d.entity_id = ?
            """,
            (
                int(
                    entity_id
                ),
            ),
        ).fetchall()

    result: dict[
        str,
        set[str],
    ] = defaultdict(
        set
    )

    for row in rows:
        result[
            str(
                row[
                    "source_name"
                ]
            )
        ].add(
            str(
                row[
                    "domain"
                ]
            )
        )

    return dict(
        result
    )


def audit_source_agreement() -> dict[str, Any]:
    entities = (
        linked_wikidata_entities()
    )

    reports = []

    exact_entities = 0
    disagreement_entities = 0
    missing_wikidata_site = 0

    for entity in entities:
        evidence = (
            evidence_domains_for_entity(
                int(
                    entity[
                        "entity_id"
                    ]
                )
            )
        )

        ror_domains = sorted(
            evidence.get(
                "ror",
                set(),
            )
        )

        wikidata_domains = sorted(
            evidence.get(
                "wikidata_p856",
                set(),
            )
        )

        comparisons = []

        for ror_domain in ror_domains:
            for wikidata_domain in (
                wikidata_domains
            ):
                relationship = (
                    classify_domain_relationship(
                        ror_domain,
                        wikidata_domain,
                    )
                )

                comparisons.append(
                    {
                        "ror_domain": (
                            ror_domain
                        ),

                        "wikidata_domain": (
                            wikidata_domain
                        ),

                        "relationship": (
                            relationship.relationship
                        ),

                        "confidence": (
                            relationship.confidence
                        ),

                        "reason": (
                            relationship.reason
                        ),
                    }
                )

        exact = any(
            item[
                "relationship"
            ]
            == "exact_agreement"

            for item in comparisons
        )

        if exact:
            state = (
                "exact_source_agreement"
            )

            exact_entities += 1

        elif not wikidata_domains:
            state = (
                "wikidata_no_website"
            )

            missing_wikidata_site += 1

        else:
            state = (
                "source_disagreement"
            )

            disagreement_entities += 1

        reports.append(
            {
                "entity_id": int(
                    entity[
                        "entity_id"
                    ]
                ),

                "canonical_name": (
                    entity[
                        "canonical_name"
                    ]
                ),

                "state": state,

                "ror_domains": (
                    ror_domains
                ),

                "wikidata_domains": (
                    wikidata_domains
                ),

                "comparisons": (
                    comparisons
                ),
            }
        )

    return {
        "linked_entities": len(
            entities
        ),

        "exact_source_agreement": (
            exact_entities
        ),

        "source_disagreement": (
            disagreement_entities
        ),

        "wikidata_no_website": (
            missing_wikidata_site
        ),

        "entities": reports,
    }
