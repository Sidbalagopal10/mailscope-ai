import json
from typing import Optional
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.scan_result import ScanResult
from app.services.risk_engine import RiskResult


def get_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.lower() or "unknown"


def gmail_scan_exists(
    database: Session,
    gmail_message_id: str,
    url: str,
) -> bool:
    existing_record = (
        database.query(ScanResult)
        .filter(
            ScanResult.gmail_message_id == gmail_message_id,
            ScanResult.url == url,
            ScanResult.source == "gmail",
        )
        .first()
    )

    return existing_record is not None


def save_scan_result(
    database: Session,
    result: RiskResult,
    source: str = "manual",
    gmail_message_id: Optional[str] = None,
    email_subject: Optional[str] = None,
    email_sender: Optional[str] = None,
) -> ScanResult:
    record = ScanResult(
        url=result.url,
        domain=get_domain(result.url),
        severity=result.severity,
        risk_level=result.risk_level,
        is_suspicious=result.is_suspicious,
        reasons=json.dumps(result.reasons),
        source=source,
        gmail_message_id=gmail_message_id,
        email_subject=email_subject,
        email_sender=email_sender,
    )

    database.add(record)
    database.commit()
    database.refresh(record)

    return record
