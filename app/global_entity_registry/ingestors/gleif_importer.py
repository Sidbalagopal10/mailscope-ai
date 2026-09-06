from __future__ import annotations

from pprint import pprint
from typing import Any

from app.global_entity_registry.gleif_repository import (
    legal_entity_summary,
    upsert_legal_entity,
)
from app.global_entity_registry.ingestors.gleif_client import (
    search_legal_name,
)
from app.global_entity_registry.ingestors.gleif_parser import (
    parse_response_records,
)


def import_search(
    name: str,
    *,
    page_size: int = 10,
) -> dict[str, Any]:
    payload = search_legal_name(
        name,
        page_size=page_size,
    )

    records = (
        parse_response_records(
            payload
        )
    )

    imported = 0

    for record in records:
        upsert_legal_entity(
            record
        )

        imported += 1

    return {
        "query": name,
        "records_received": len(
            records
        ),
        "records_imported": (
            imported
        ),
        "summary": (
            legal_entity_summary()
        ),
        "records": records,
    }


if __name__ == "__main__":
    for query in [
        "Microsoft",
        "NVIDIA",
        "Apple",
    ]:
        print()
        print("=" * 70)
        print(query)

        result = import_search(
            query,
            page_size=5,
        )

        pprint(
            {
                "query": result[
                    "query"
                ],
                "records_received": (
                    result[
                        "records_received"
                    ]
                ),
                "summary": result[
                    "summary"
                ],
            },
            sort_dicts=False,
        )
