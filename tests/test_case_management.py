from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.case_management.repository import (
    add_note,
    attach_investigation,
    create_case,
    get_case,
    list_cases,
    update_case,
)
from app.database.database import Base


def make_db():
    engine = create_engine(
        "sqlite://",
        connect_args={
            "check_same_thread": False
        },
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    Session = sessionmaker(
        bind=engine
    )

    return Session()


def test_create_and_get_case():
    db = make_db()

    case = create_case(
        db,
        "Phishing Campaign",
        "high",
        ["inv-1"],
    )

    loaded = get_case(
        db,
        case["case_id"],
    )

    assert loaded["title"] == "Phishing Campaign"
    assert loaded["priority"] == "high"
    assert loaded["investigation_ids"] == ["inv-1"]


def test_attach_investigation_is_unique():
    db = make_db()

    case = create_case(
        db,
        "Test",
    )

    attach_investigation(
        db,
        case["case_id"],
        "inv-1",
    )

    updated = attach_investigation(
        db,
        case["case_id"],
        "inv-1",
    )

    assert updated[
        "investigation_ids"
    ] == ["inv-1"]


def test_add_note():
    db = make_db()

    case = create_case(
        db,
        "Test",
    )

    updated = add_note(
        db,
        case["case_id"],
        "Escalated to analyst.",
    )

    assert len(
        updated["notes"]
    ) == 1


def test_update_case():
    db = make_db()

    case = create_case(
        db,
        "Test",
    )

    updated = update_case(
        db,
        case["case_id"],
        status="investigating",
        priority="critical",
    )

    assert updated["status"] == "investigating"
    assert updated["priority"] == "critical"


def test_list_cases():
    db = make_db()

    create_case(db, "One")
    create_case(db, "Two")

    assert len(
        list_cases(db)
    ) == 2
