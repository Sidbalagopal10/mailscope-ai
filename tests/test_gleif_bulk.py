from __future__ import annotations

from pathlib import Path

from app.global_entity_registry.ingestors.gleif_bulk_parser import (
    iter_lei_records,
)


FIXTURE = Path(
    "tests/fixtures/gleif_sample.zip"
)


def test_bulk_record_parses():
    records = list(
        iter_lei_records(
            FIXTURE
        )
    )

    assert len(
        records
    ) == 1

    record = records[0]

    assert (
        record[
            "lei"
        ]
        == "5493001KJTIIGC8Y1R12"
    )

    assert (
        record[
            "legal_name"
        ].strip()
        == "EXAMPLE CORPORATION"
    )

    assert (
        record[
            "legal_address_country"
        ]
        == "US"
    )

    assert (
        record[
            "headquarters_city"
        ]
        == "San Francisco"
    )

    assert (
        record[
            "entity_status"
        ]
        == "ACTIVE"
    )
