from __future__ import annotations

from app.global_entity_registry.ingestors.ror_parser import (
    parse_ror_record,
)


def sample_record():
    return {
        "id": "https://ror.org/123456789",
        "status": "active",
        "domains": [
            "example.edu"
        ],
        "types": [
            "education"
        ],
        "names": [
            {
                "value": "EU",
                "types": [
                    "acronym"
                ],
                "lang": "en",
            },
            {
                "value": "Example University",
                "types": [
                    "ror_display",
                    "label",
                ],
                "lang": "en",
            },
            {
                "value": "Universidad Ejemplo",
                "types": [
                    "label"
                ],
                "lang": "es",
            },
        ],
        "locations": [
            {
                "geonames_details": {
                    "country_code": "US",
                    "country_name": (
                        "United States"
                    ),
                    "continent_name": (
                        "North America"
                    ),
                }
            }
        ],
        "external_ids": [
            {
                "type": "wikidata",
                "preferred": "Q12345",
                "all": [
                    "Q12345"
                ],
            }
        ],
        "links": [
            {
                "type": "website",
                "value": (
                    "https://www.example.edu/"
                ),
            }
        ],
    }


def test_parse_ror_record():
    parsed = parse_ror_record(
        sample_record()
    )

    assert parsed is not None

    assert (
        parsed.canonical_name
        == "Example University"
    )

    assert (
        parsed.entity_type
        == "education"
    )

    assert (
        parsed.country_code
        == "US"
    )

    assert (
        parsed.continent
        == "North America"
    )

    assert (
        parsed.domains
        == [
            "example.edu"
        ]
    )

    assert (
        "Universidad Ejemplo"
        in parsed.aliases
    )

    assert (
        parsed.external_ids[
            "wikidata"
        ]
        == "Q12345"
    )


def test_inactive_record_skipped():
    record = sample_record()

    record[
        "status"
    ] = "inactive"

    assert (
        parse_ror_record(
            record
        )
        is None
    )


def test_website_fallback_domain():
    record = sample_record()

    record[
        "domains"
    ] = []

    parsed = parse_ror_record(
        record
    )

    assert parsed is not None

    assert (
        parsed.domains
        == [
            "example.edu"
        ]
    )
