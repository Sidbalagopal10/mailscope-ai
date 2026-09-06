from __future__ import annotations

from app.global_entity_registry.ingestors.wikidata_enricher import (
    english_aliases,
    normalize_qid,
    official_websites,
)
from app.global_entity_registry.public_suffix import (
    domain_relationship,
    registrable_domain,
)


def test_qid_normalization():
    assert (
        normalize_qid(
            "https://www.wikidata.org/entity/Q95"
        )
        == "Q95"
    )


def test_official_website_extraction():
    entity = {
        "claims": {
            "P856": [
                {
                    "mainsnak": {
                        "datavalue": {
                            "value": (
                                "https://www.example.org/"
                            )
                        }
                    }
                }
            ]
        }
    }

    assert official_websites(
        entity
    ) == [
        "https://www.example.org/"
    ]


def test_alias_extraction():
    entity = {
        "aliases": {
            "en": [
                {
                    "language": "en",
                    "value": "Example Org",
                }
            ]
        }
    }

    assert english_aliases(
        entity
    ) == [
        "Example Org"
    ]


def test_public_suffix_co_uk():
    assert (
        registrable_domain(
            "news.bbc.co.uk"
        )
        == "bbc.co.uk"
    )


def test_public_suffix_gov_in():
    assert (
        registrable_domain(
            "www.isro.gov.in"
        )
        == "isro.gov.in"
    )


def test_deceptive_suffix_relationship():
    assert (
        domain_relationship(
            "google.com.attacker.example",
            "google.com",
        )
        == "unrelated"
    )


def test_true_subdomain_relationship():
    assert (
        domain_relationship(
            "accounts.google.com",
            "google.com",
        )
        == "true_subdomain"
    )
