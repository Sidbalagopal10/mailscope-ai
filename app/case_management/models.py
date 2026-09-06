from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String, Text

from app.database.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class SecurityCase(Base):
    __tablename__ = "security_cases"

    case_id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    status = Column(String, nullable=False, default="open")
    priority = Column(String, nullable=False, default="medium")
    investigation_ids_json = Column(Text, nullable=False, default="[]")
    notes_json = Column(Text, nullable=False, default="[]")

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )
