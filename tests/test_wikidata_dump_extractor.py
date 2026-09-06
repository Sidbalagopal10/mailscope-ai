from __future__ import annotations

from pathlib import Path

from app.global_entity_registry.ingestors.wikidata_dump_extractor import (
    entity_to_record,
    iter_json_array_dump,
    official_websites,
)
from app.global_entity_registry.wikidata_categories import (
    classify_entity,
)


FIXTURE = Path(
    "tests/fixtures/"
    "wikidata_sample.json"
)

COMPRESSED_FIXTURE = Path(
    "tests/fixtures/"
    "wikidata_sample.json.bz2"
)


def records():
    return list(
        iter_json_array_dump(
            FIXTURE
        )
    )


def test_stream_json_dump():
    items = records()

    assert len(
        items
    ) == 5


def test_stream_bz2_dump():
    items = list(
        iter_json_array_dump(
            COMPRESSED_FIXTURE
        )
    )

    assert len(
        items
    ) == 5


def test_p856_extraction():
    item = records()[0]

    assert official_websites(
        item
    ) == [
        "https://www.example.edu/"
    ]


def test_university_classification():
    result = classify_entity(
        records()[0]
    )

    assert (
        result[
            "primary_category"
        ]
        == "education"
    )


def test_hospital_classification():
    result = classify_entity(
        records()[1]
    )

    assert (
        result[
            "primary_category"
        ]
        == "healthcare"
    )


def test_sports_classification():
    result = classify_entity(
        records()[3]
    )

    assert (
        result[
            "primary_category"
        ]
        == "sports"
    )


def test_unclassified_entity_is_retained():
    record = entity_to_record(
        records()[4]
    )

    assert record is not None

    assert (
        record.entity_type
        == "unclassified"
    )

    assert record.domains == [
        "unknown-sector.example"
    ]


def test_no_website_is_skipped():
    result = entity_to_record(
        records()[2]
    )

    assert result is None


def test_qid_is_preserved():
    result = entity_to_record(
        records()[0]
    )

    assert result is not None

    assert (
        result.external_ids[
            "wikidata"
        ]
        == "Q1001"
    )
