import json
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.case_management.models import SecurityCase


VALID_STATUS = {
    "open",
    "investigating",
    "contained",
    "closed",
}

VALID_PRIORITY = {
    "low",
    "medium",
    "high",
    "critical",
}


def _now():
    return datetime.now(timezone.utc)


def _loads(value):
    try:
        return json.loads(value or "[]")
    except (TypeError, json.JSONDecodeError):
        return []


def serialize_case(case):
    return {
        "case_id": case.case_id,
        "title": case.title,
        "status": case.status,
        "priority": case.priority,
        "investigation_ids": _loads(case.investigation_ids_json),
        "notes": _loads(case.notes_json),
        "created_at": (
            case.created_at.isoformat()
            if case.created_at
            else None
        ),
        "updated_at": (
            case.updated_at.isoformat()
            if case.updated_at
            else None
        ),
    }


def create_case(
    db: Session,
    title: str,
    priority: str = "medium",
    investigation_ids=None,
):
    priority = priority.lower()

    if priority not in VALID_PRIORITY:
        raise ValueError("Invalid case priority.")

    case = SecurityCase(
        case_id="case-" + uuid.uuid4().hex[:12],
        title=title.strip(),
        status="open",
        priority=priority,
        investigation_ids_json=json.dumps(
            list(dict.fromkeys(investigation_ids or []))
        ),
        notes_json="[]",
    )

    db.add(case)
    db.commit()
    db.refresh(case)

    return serialize_case(case)


def get_case(
    db: Session,
    case_id: str,
):
    case = db.get(
        SecurityCase,
        case_id,
    )

    if case is None:
        return None

    return serialize_case(case)


def list_cases(
    db: Session,
    limit: int = 100,
):
    rows = (
        db.query(SecurityCase)
        .order_by(SecurityCase.updated_at.desc())
        .limit(limit)
        .all()
    )

    return [
        serialize_case(row)
        for row in rows
    ]


def update_case(
    db: Session,
    case_id: str,
    *,
    status=None,
    priority=None,
):
    case = db.get(
        SecurityCase,
        case_id,
    )

    if case is None:
        return None

    if status is not None:
        status = status.lower()

        if status not in VALID_STATUS:
            raise ValueError("Invalid case status.")

        case.status = status

    if priority is not None:
        priority = priority.lower()

        if priority not in VALID_PRIORITY:
            raise ValueError("Invalid case priority.")

        case.priority = priority

    case.updated_at = _now()

    db.commit()
    db.refresh(case)

    return serialize_case(case)


def attach_investigation(
    db: Session,
    case_id: str,
    investigation_id: str,
):
    case = db.get(
        SecurityCase,
        case_id,
    )

    if case is None:
        return None

    ids = _loads(
        case.investigation_ids_json
    )

    if investigation_id not in ids:
        ids.append(investigation_id)

    case.investigation_ids_json = json.dumps(ids)
    case.updated_at = _now()

    db.commit()
    db.refresh(case)

    return serialize_case(case)


def add_note(
    db: Session,
    case_id: str,
    note: str,
):
    case = db.get(
        SecurityCase,
        case_id,
    )

    if case is None:
        return None

    notes = _loads(
        case.notes_json
    )

    notes.append(
        {
            "note_id": (
                "note-"
                + uuid.uuid4().hex[:10]
            ),
            "text": note.strip(),
            "created_at": _now().isoformat(),
        }
    )

    case.notes_json = json.dumps(notes)
    case.updated_at = _now()

    db.commit()
    db.refresh(case)

    return serialize_case(case)
