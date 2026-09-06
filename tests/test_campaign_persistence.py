from __future__ import annotations

from sqlalchemy import (
    create_engine,
)
from sqlalchemy.orm import (
    sessionmaker,
)
from sqlalchemy.pool import (
    StaticPool,
)

from app.database.database import Base
from app.campaign_detection.database_models import (
    CampaignRecord,
)
from app.campaign_detection.models import (
    CampaignCandidate,
    CampaignRelationship,
    CorrelationArtifact,
)
from app.campaign_detection.repository import (
    find_campaigns_by_artifact,
    find_campaigns_by_investigation,
    get_campaign,
    list_campaigns,
    save_campaign,
)


def make_database():
    engine = create_engine(
        "sqlite://",
        connect_args={
            "check_same_thread": False
        },
        poolclass=StaticPool,
    )

    Base.metadata.create_all(
        bind=engine
    )

    Session = sessionmaker(
        bind=engine
    )

    return Session()


def campaign(
    campaign_id: str = "campaign-test",
):
    return CampaignCandidate(
        campaign_id=campaign_id,
        investigation_ids=[
            "INV-A",
            "INV-B",
        ],
        relationships=[
            CampaignRelationship(
                investigation_a="INV-A",
                investigation_b="INV-B",
                artifact_type="domain",
                artifact_value="evil.example",
                strength=0.60,
                rationale=(
                    "Same normalized domain."
                ),
            )
        ],
        shared_artifacts=[
            CorrelationArtifact(
                type="domain",
                value="evil.example",
                source="test",
                confidence=1.0,
            )
        ],
        correlation_score=0.60,
        strength="moderate",
        first_seen=(
            "2026-09-01T10:00:00+00:00"
        ),
        last_seen=(
            "2026-09-02T10:00:00+00:00"
        ),
        metadata={
            "deterministic": True,
            "ai_used": False,
        },
    )


def test_save_and_get_campaign():
    db = make_database()

    saved = save_campaign(
        db,
        campaign(),
    )

    loaded = get_campaign(
        db,
        saved.campaign_id,
    )

    assert loaded is not None
    assert loaded.campaign_id == (
        "campaign-test"
    )

    assert loaded.investigation_ids == [
        "INV-A",
        "INV-B",
    ]


def test_save_is_upsert():
    db = make_database()

    original = campaign()

    save_campaign(
        db,
        original,
    )

    updated = campaign()

    updated.correlation_score = 0.90
    updated.strength = "strong"

    save_campaign(
        db,
        updated,
    )

    rows = (
        db.query(
            CampaignRecord
        )
        .all()
    )

    assert len(rows) == 1

    loaded = get_campaign(
        db,
        "campaign-test",
    )

    assert loaded is not None
    assert loaded.correlation_score == 0.90
    assert loaded.strength == "strong"


def test_list_campaigns():
    db = make_database()

    save_campaign(
        db,
        campaign(
            "campaign-one"
        ),
    )

    save_campaign(
        db,
        campaign(
            "campaign-two"
        ),
    )

    results = list_campaigns(
        db
    )

    assert len(results) == 2


def test_find_by_investigation():
    db = make_database()

    save_campaign(
        db,
        campaign(),
    )

    results = (
        find_campaigns_by_investigation(
            db,
            "INV-A",
        )
    )

    assert len(results) == 1

    assert results[
        0
    ].campaign_id == (
        "campaign-test"
    )


def test_unknown_investigation_returns_empty():
    db = make_database()

    save_campaign(
        db,
        campaign(),
    )

    assert (
        find_campaigns_by_investigation(
            db,
            "INV-NOT-THERE",
        )
        == []
    )


def test_find_by_artifact():
    db = make_database()

    save_campaign(
        db,
        campaign(),
    )

    results = find_campaigns_by_artifact(
        db,
        artifact_type="domain",
        artifact_value="EVIL.EXAMPLE",
    )

    assert len(results) == 1

    assert results[
        0
    ].campaign_id == (
        "campaign-test"
    )


def test_unknown_artifact_returns_empty():
    db = make_database()

    save_campaign(
        db,
        campaign(),
    )

    assert (
        find_campaigns_by_artifact(
            db,
            artifact_type="domain",
            artifact_value="safe.example",
        )
        == []
    )


def test_round_trip_preserves_relationships():
    db = make_database()

    save_campaign(
        db,
        campaign(),
    )

    loaded = get_campaign(
        db,
        "campaign-test",
    )

    assert loaded is not None

    assert len(
        loaded.relationships
    ) == 1

    relationship = (
        loaded.relationships[
            0
        ]
    )

    assert (
        relationship.artifact_type
        == "domain"
    )

    assert (
        relationship.artifact_value
        == "evil.example"
    )


def test_round_trip_preserves_security_metadata():
    db = make_database()

    save_campaign(
        db,
        campaign(),
    )

    loaded = get_campaign(
        db,
        "campaign-test",
    )

    assert loaded is not None

    assert loaded.metadata[
        "deterministic"
    ] is True

    assert loaded.metadata[
        "ai_used"
    ] is False
