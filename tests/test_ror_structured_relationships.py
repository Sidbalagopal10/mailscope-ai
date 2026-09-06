from __future__ import annotations

from app.global_entity_registry.ingestors.ror_parser import (
    parse_ror_record,
)


def base_record() -> dict:
    return {
        "id": "https://ror.org/012345678",
        "status": "active",
        "names": [
            {
                "value": "Example Organization",
                "types": [
                    "ror_display",
                ],
            }
        ],
        "types": [
            "company",
        ],
        "locations": [],
        "external_ids": [],
        "aliases": [],
    }


def test_regular_ror_website_becomes_domain_identity():
    record = base_record()

    record[
        "domains"
    ] = []

    record[
        "links"
    ] = [
        {
            "type": "website",
            "value": (
                "https://example-organization.org/"
            ),
        }
    ]

    parsed = parse_ror_record(
        record
    )

    assert parsed is not None

    assert (
        "example-organization.org"
        in parsed.domains
    )

    assert (
        parsed.website_relationships
    )

    relationship = (
        parsed.website_relationships[
            0
        ]
    )

    assert (
        relationship.relationship_type
        == "official_website_candidate"
    )

    assert (
        relationship.eligible_for_domain_identity
        is True
    )


def test_github_fallback_does_not_become_domain_identity():
    record = base_record()

    record[
        "domains"
    ] = []

    record[
        "links"
    ] = [
        {
            "type": "website",
            "value": (
                "https://github.com/"
                "Example-Organization"
            ),
        }
    ]

    parsed = parse_ror_record(
        record
    )

    assert parsed is not None

    assert (
        "github.com"
        not in parsed.domains
    )

    github = [
        relationship
        for relationship
        in parsed.website_relationships
        if (
            relationship.provider
            == "GitHub"
        )
    ]

    assert github

    assert (
        github[
            0
        ].relationship_type
        == "code_repository"
    )

    assert (
        github[
            0
        ].eligible_for_domain_identity
        is False
    )


def test_linkedin_does_not_become_domain_identity():
    record = base_record()

    record[
        "domains"
    ] = []

    record[
        "links"
    ] = [
        {
            "type": "website",
            "value": (
                "https://linkedin.com/"
                "company/example"
            ),
        }
    ]

    parsed = parse_ror_record(
        record
    )

    assert parsed is not None

    assert (
        "linkedin.com"
        not in parsed.domains
    )


def test_explicit_ror_domain_still_survives():
    record = base_record()

    record[
        "domains"
    ] = [
        "example.org",
    ]

    record[
        "links"
    ] = []

    parsed = parse_ror_record(
        record
    )

    assert parsed is not None

    assert (
        "example.org"
        in parsed.domains
    )


def test_platform_relationship_preserved_even_when_not_identity():
    record = base_record()

    record[
        "domains"
    ] = []

    record[
        "links"
    ] = [
        {
            "type": "website",
            "value": (
                "https://example.pages.dev/"
            ),
        }
    ]

    parsed = parse_ror_record(
        record
    )

    assert parsed is not None

    assert (
        "example.pages.dev"
        not in parsed.domains
    )

    assert any(
        relationship.hostname
        == "example.pages.dev"
        and relationship.preserve_as_relationship
        for relationship
        in parsed.website_relationships
    )


def test_www_and_root_collapse_to_one_identity_domain():
    record = base_record()

    record[
        "domains"
    ] = [
        "example.edu",
    ]

    record[
        "links"
    ] = [
        {
            "type": "website",
            "value": (
                "https://www.example.edu/"
            ),
        }
    ]

    parsed = parse_ror_record(
        record
    )

    assert parsed is not None

    assert (
        parsed.domains
        == [
            "example.edu",
        ]
    )
