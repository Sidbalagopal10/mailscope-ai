from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text

from app.database.database import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)

    url = Column(
        Text,
        nullable=False,
    )

    domain = Column(
        String(255),
        nullable=False,
        index=True,
    )

    severity = Column(
        Float,
        nullable=False,
    )

    risk_level = Column(
        String(20),
        nullable=False,
        index=True,
    )

    is_suspicious = Column(
        Boolean,
        nullable=False,
    )

    reasons = Column(
        Text,
        nullable=False,
        default="",
    )

    source = Column(
        String(30),
        nullable=False,
        default="manual",
        index=True,
    )

    gmail_message_id = Column(
        String(255),
        nullable=True,
        index=True,
    )

    email_subject = Column(
        Text,
        nullable=True,
    )

    email_sender = Column(
        Text,
        nullable=True,
    )

    scanned_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )
