from __future__ import annotations

from pathlib import Path

import pytest

from app.global_entity_registry import (
    database,
    repository,
)
from app.global_entity_registry.domain_utils import (
    is_exact_or_subdomain,
    normalize_hostname,
)
from app.global_entity_registry.models import (
    EntityRecord,
    SourceEvidence,
)


@pytest.fixture()
def isolated_database(
    tmp_path,
    monkeypatch,
):
    path = (
        tmp_path
        / "registry.db"
    )

    monkeypatch.setattr(
        database,
        "DEFAULT_DATABASE_PATH",
        path,
    )

    monkeypatch.setattr(
        repository,
        "connection",
        lambda: database.connection(
            path
        ),
    )

    return path


def test_hostname_normalization():
    assert (
        normalize_hostname(
            "HTTPS://WWW.Example.COM/path"
        )
        == "www.example.com"
    )


def test_true_subdomain():
    assert is_exact_or_subdomain(
        "accounts.google.com",
        "google.com",
    )


def test_deceptive_domain_not_subdomain():
    assert not is_exact_or_subdomain(
        "google.com.attacker.test",
        "google.com",
    )


def test_unknown_domain_is_neutral(
    isolated_database,
):
    result = repository.lookup_domain(
        "unknown-example.test"
    )

    assert not result[
        "matched"
    ]

    assert result[
        "identity_state"
    ] == "unknown"

    assert result[
        "security_effect"
    ] == "neutral"


def test_verified_domain_roundtrip(
    isolated_database,
):
    record = EntityRecord(
        canonical_name="Example University",
        entity_type="education",
        country_code="GB",
        country_name="United Kingdom",
        continent="Europe",
        domains=[
            "example.ac.uk"
        ],
        evidence={
            "example.ac.uk": [
                SourceEvidence(
                    source_name="test",
                    confidence=0.95,
                    authoritative=True,
                )
            ]
        },
    )

    repository.upsert_entity(
        record
    )

    result = repository.lookup_domain(
        "portal.example.ac.uk"
    )

    assert result[
        "matched"
    ]

    assert result[
        "identity_state"
    ] == "verified_official"

    assert result[
        "entity"
    ][
        "name"
    ] == "Example University"


def test_lookalike_does_not_inherit_identity(
    isolated_database,
):
    repository.upsert_entity(
        EntityRecord(
            canonical_name="Example Corporation",
            entity_type="company",
            domains=[
                "example.com"
            ],
        )
    )

    result = repository.lookup_domain(
        "example-login.test"
    )

    assert not result[
        "matched"
    ]
