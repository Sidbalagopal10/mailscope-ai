from pathlib import Path

from app.organization_intelligence import (
    store,
)
from app.organization_intelligence.sources import (
    cisa_dotgov,
)


CSV_CONTENT = """Domain name,Domain type,Organization name,Suborganization name,City,State,Security contact email
examplecity.gov,City,City of Example,,Example City,VA,security@examplecity.gov
exampleschools.gov,School District,Example Public Schools,,Example,MD,security@exampleschools.gov
"""


def test_validate_cisa_dataset(
    tmp_path,
):
    csv_path = (
        tmp_path
        / "dotgov.csv"
    )

    csv_path.write_text(
        CSV_CONTENT,
        encoding="utf-8",
    )

    result = (
        cisa_dotgov.validate_dataset(
            csv_path
        )
    )

    assert result["valid"]
    assert result["row_count"] == 2


def test_import_cisa_dataset(
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
        / "dotgov.csv"
    )

    csv_path.write_text(
        CSV_CONTENT,
        encoding="utf-8",
    )

    result = (
        cisa_dotgov.import_dataset(
            path=csv_path
        )
    )

    assert result["imported"] == 2
    assert result["failed"] == 0

    city = store.resolve_domain(
        "services.examplecity.gov"
    )

    assert city is not None

    assert (
        city["legal_name"]
        == "City of Example"
    )

    assert (
        city["identity_state"]
        == "VERIFIED_ESTABLISHED"
    )

    school = store.resolve_domain(
        "exampleschools.gov"
    )

    assert school is not None
    assert school["entity_type"] == "school"


def test_security_email_is_not_stored(
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
        / "dotgov.csv"
    )

    csv_path.write_text(
        CSV_CONTENT,
        encoding="utf-8",
    )

    cisa_dotgov.import_dataset(
        path=csv_path
    )

    database_bytes = (
        store.DATABASE_PATH.read_bytes()
    )

    assert (
        b"security@examplecity.gov"
        not in database_bytes
    )
