from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    String,
    Text,
)

from app.database.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CampaignRecord(Base):
    __tablename__ = "campaign_detection_records"

    campaign_id = Column(
        String(128),
        primary_key=True,
    )

    investigation_ids_json = Column(
        Text,
        nullable=False,
    )

    relationships_json = Column(
        Text,
        nullable=False,
    )

    shared_artifacts_json = Column(
        Text,
        nullable=False,
    )

    correlation_score = Column(
        Float,
        nullable=False,
    )

    strength = Column(
        String(32),
        nullable=False,
    )

    first_seen = Column(
        String(64),
        nullable=True,
    )

    last_seen = Column(
        String(64),
        nullable=True,
    )

    metadata_json = Column(
        Text,
        nullable=False,
    )

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )

    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )
