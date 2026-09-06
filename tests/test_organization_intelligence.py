from pathlib import Path

from app.organization_intelligence import (
    store,
)
from app.organization_intelligence.scoring import (
    identity_score_adjustment,
)


def test_unknown_domain_is_neutral(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        store,
        "DATABASE_PATH",
        tmp_path / "registry.db",
    )

    result = identity_score_adjustment(
        "unknown-organization.example"
    )

    assert not result[
        "matched"
    ]

    assert (
        result["score_adjustment"]
        == 0
    )


def test_verified_domain_resolves(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        store,
        "DATABASE_PATH",
        tmp_path / "registry.db",
    )

    store.upsert_organization_domain(
        legal_name="Example University",
        entity_type="university",
        domain="example.edu",
        source_name="Education Registry",
        source_type="education_registry",
        source_record_id="123",
        authoritative_source=True,
        country_code="US",
        identity_state=(
            "VERIFIED_ESTABLISHED"
        ),
        security_state="CLEAN",
        identity_confidence=95,
        security_confidence=80,
    )

    result = store.resolve_domain(
        "admissions.example.edu"
    )

    assert result is not None

    assert (
        result["legal_name"]
        == "Example University"
    )

    score = identity_score_adjustment(
        "admissions.example.edu"
    )

    assert score["matched"]

    assert (
        score["score_adjustment"]
        < 0
    )


def test_compromised_legitimate_domain_increases_risk(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        store,
        "DATABASE_PATH",
        tmp_path / "registry.db",
    )

    store.upsert_organization_domain(
        legal_name="Example Corporation",
        entity_type="corporation",
        domain="example-corp.com",
        source_name="Corporate Registry",
        source_type="corporate_registry",
        authoritative_source=True,
        identity_state=(
            "VERIFIED_ESTABLISHED"
        ),
        security_state=(
            "COMPROMISED_LEGITIMATE"
        ),
        identity_confidence=95,
        security_confidence=95,
    )

    result = identity_score_adjustment(
        "example-corp.com"
    )

    assert (
        result["score_adjustment"]
        > 0
    )


def test_csv_import(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        store,
        "DATABASE_PATH",
        tmp_path / "registry.db",
    )

    csv_path = (
        tmp_path
        / "organizations.csv"
    )

    csv_path.write_text(
        (
            "legal_name,entity_type,domain,"
            "source_name,source_type,"
            "authoritative_source,"
            "identity_state,security_state\n"
            "Test Bank,bank,testbank.example,"
            "Bank Registry,bank_registry,true,"
            "VERIFIED_ESTABLISHED,NEUTRAL\n"
        ),
        encoding="utf-8",
    )

    result = store.import_csv_file(
        csv_path
    )

    assert result["imported"] == 1
    assert result["failed"] == 0
