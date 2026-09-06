from __future__ import annotations

from app.global_entity_registry.gleif_repository import (
    name_similarity,
)
from app.global_entity_registry.gleif_resolution import (
    candidate_score,
)
from app.global_entity_registry.ingestors.gleif_parser import (
    parse_lei_resource,
)


def sample_resource():
    return {
        "id": (
            "5493001KJTIIGC8Y1R12"
        ),
        "attributes": {
            "entity": {
                "legalName": {
                    "name": (
                        "EXAMPLE CORPORATION"
                    ),
                    "language": "en",
                },
                "otherNames": [
                    {
                        "name": (
                            "Example Corp"
                        ),
                        "type": (
                            "TRADING_OR_OPERATING_NAME"
                        ),
                        "language": "en",
                    }
                ],
                "status": "ACTIVE",
                "jurisdiction": "US-DE",
                "legalForm": {
                    "id": "XXXX"
                },
                "registeredAt": {
                    "id": "RA000602"
                },
                "registeredAs": (
                    "1234567"
                ),
                "legalAddress": {
                    "country": "US",
                    "region": "US-DE",
                    "city": "Wilmington",
                },
                "headquartersAddress": {
                    "country": "US",
                    "region": "US-CA",
                    "city": "San Francisco",
                },
            },
            "registration": {
                "initialRegistrationDate": (
                    "2020-01-01T00:00:00Z"
                ),
                "lastUpdateDate": (
                    "2026-01-01T00:00:00Z"
                ),
                "nextRenewalDate": (
                    "2027-01-01T00:00:00Z"
                ),
                "managingLou": (
                    "TESTLOU123"
                ),
            },
        },
    }


def test_parse_lei_resource():
    result = parse_lei_resource(
        sample_resource()
    )

    assert result is not None

    assert (
        result[
            "legal_name"
        ]
        == "EXAMPLE CORPORATION"
    )

    assert (
        result[
            "legal_address_country"
        ]
        == "US"
    )

    assert (
        result[
            "entity_status"
        ]
        == "ACTIVE"
    )

    assert (
        result[
            "other_names"
        ][0][
            "name"
        ]
        == "Example Corp"
    )


def test_identical_names():
    assert (
        name_similarity(
            "Microsoft Corporation",
            "Microsoft Corporation",
        )
        == 1.0
    )


def test_candidate_country_agreement():
    result = candidate_score(
        registry_name=(
            "Example Corporation"
        ),
        legal_name=(
            "EXAMPLE CORPORATION"
        ),
        registry_country="US",
        gleif_country="US",
    )

    assert (
        result[
            "confidence"
        ]
        == 1.0
    )

    assert (
        result[
            "decision"
        ]
        == "high_confidence_candidate"
    )


def test_name_alone_does_not_create_verified_link():
    result = candidate_score(
        registry_name="ABC",
        legal_name="ABC",
        registry_country=None,
        gleif_country=None,
    )

    assert (
        result[
            "confidence"
        ]
        < 1.0
    )

    assert (
        result[
            "decision"
        ]
        != "high_confidence_candidate"
    )
