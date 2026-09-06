from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from app.global_entity_registry.database import connection


REPORT = Path(
    "data/organization_graph/"
    "latest_domain_integrity_report.json"
)


def audit_domain_ownership() -> dict[str, Any]:
    with connection() as db:
        rows = db.execute(
            """
            SELECT
                d.id AS graph_domain_id,
                d.node_id,
                d.domain,
                d.relationship_type,
                d.confidence,
                d.source_count,

                n.canonical_name,
                n.entity_type,
                n.country_code

            FROM organization_graph_domains d

            JOIN organization_graph_nodes n
              ON n.id = d.node_id

            ORDER BY d.domain
            """
        ).fetchall()

    grouped: dict[str, list[dict[str, Any]]] = (
        defaultdict(list)
    )

    for row in rows:
        grouped[
            str(row["domain"]).lower()
        ].append(
            dict(row)
        )

    conflicts = []

    single_source = []

    for domain, claims in grouped.items():
        unique_nodes = {
            int(item["node_id"])
            for item in claims
        }

        if len(unique_nodes) > 1:
            conflicts.append(
                {
                    "domain": domain,
                    "claim_count": len(claims),
                    "claims": claims,
                }
            )

        for claim in claims:
            if int(
                claim["source_count"] or 0
            ) <= 1:
                single_source.append(
                    claim
                )

    report = {
        "domains_examined": len(grouped),
        "conflicting_domains": len(conflicts),
        "single_source_claims": len(
            single_source
        ),
        "conflicts": conflicts,
    }

    REPORT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
            default=str,
        ),
        encoding="utf-8",
    )

    return report


def quarantine_conflicting_claims() -> dict[str, int]:
    report = audit_domain_ownership()

    quarantined = 0
    verified = 0
    supported = 0

    conflict_domains = {
        item["domain"]
        for item in report["conflicts"]
    }

    with connection() as db:
        rows = db.execute(
            """
            SELECT
                id,
                domain,
                source_count
            FROM organization_graph_domains
            """
        ).fetchall()

        for row in rows:
            domain = str(
                row["domain"]
            ).lower()

            source_count = int(
                row["source_count"] or 0
            )

            if domain in conflict_domains:
                db.execute(
                    """
                    UPDATE organization_graph_domains

                    SET
                        integrity_state = 'conflicting',
                        integrity_reason =
                            'Multiple organization nodes claim this domain.',
                        usable_for_identity = 0

                    WHERE id = ?
                    """,
                    (
                        int(row["id"]),
                    ),
                )

                quarantined += 1

            elif source_count >= 2:
                db.execute(
                    """
                    UPDATE organization_graph_domains

                    SET
                        integrity_state = 'corroborated',
                        integrity_reason =
                            'Multiple independent sources support this relationship.',
                        usable_for_identity = 1

                    WHERE id = ?
                    """,
                    (
                        int(row["id"]),
                    ),
                )

                verified += 1

            else:
                db.execute(
                    """
                    UPDATE organization_graph_domains

                    SET
                        integrity_state = 'single_source',
                        integrity_reason =
                            'Only one source currently supports this relationship.',
                        usable_for_identity = 1

                    WHERE id = ?
                    """,
                    (
                        int(row["id"]),
                    ),
                )

                supported += 1

        db.commit()

    return {
        "quarantined_claims": quarantined,
        "corroborated_claims": verified,
        "single_source_claims": supported,
    }


if __name__ == "__main__":
    from pprint import pprint

    pprint(
        quarantine_conflicting_claims(),
        sort_dicts=False,
    )
