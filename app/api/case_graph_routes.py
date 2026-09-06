from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
)
from pydantic import (
    BaseModel,
    Field,
)
from sqlalchemy.orm import Session

from app.case_management.repository import (
    add_note,
    attach_investigation,
    create_case,
    get_case,
    list_cases,
    update_case,
)
from app.database.database import (
    get_database,
)
from app.threat_graph.engine import (
    build_threat_graph,
)
from app.threat_hunting.report_loader import (
    load_investigation_reports,
)


router = APIRouter(
    tags=[
        "Case Management",
        "Threat Graph",
    ]
)


class CreateCaseRequest(BaseModel):
    title: str = Field(min_length=1)
    priority: str = "medium"
    investigation_ids: list[str] = Field(
        default_factory=list
    )


class UpdateCaseRequest(BaseModel):
    status: str | None = None
    priority: str | None = None


class AttachInvestigationRequest(BaseModel):
    investigation_id: str = Field(
        min_length=1
    )


class AddNoteRequest(BaseModel):
    note: str = Field(
        min_length=1
    )


@router.post("/cases")
def api_create_case(
    request: CreateCaseRequest,
    db: Session = Depends(
        get_database
    ),
):
    try:
        return create_case(
            db,
            request.title,
            request.priority,
            request.investigation_ids,
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error


@router.get("/cases")
def api_list_cases(
    limit: int = Query(
        default=100,
        ge=1,
        le=1000,
    ),
    db: Session = Depends(
        get_database
    ),
):
    cases = list_cases(
        db,
        limit,
    )

    return {
        "count": len(cases),
        "cases": cases,
    }


@router.get("/cases/{case_id}")
def api_get_case(
    case_id: str,
    db: Session = Depends(
        get_database
    ),
):
    case = get_case(
        db,
        case_id,
    )

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Case not found.",
        )

    return case


@router.patch("/cases/{case_id}")
def api_update_case(
    case_id: str,
    request: UpdateCaseRequest,
    db: Session = Depends(
        get_database
    ),
):
    try:
        case = update_case(
            db,
            case_id,
            status=request.status,
            priority=request.priority,
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Case not found.",
        )

    return case


@router.post(
    "/cases/{case_id}/investigations"
)
def api_attach_investigation(
    case_id: str,
    request: AttachInvestigationRequest,
    db: Session = Depends(
        get_database
    ),
):
    case = attach_investigation(
        db,
        case_id,
        request.investigation_id,
    )

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Case not found.",
        )

    return case


@router.post(
    "/cases/{case_id}/notes"
)
def api_add_note(
    case_id: str,
    request: AddNoteRequest,
    db: Session = Depends(
        get_database
    ),
):
    case = add_note(
        db,
        case_id,
        request.note,
    )

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Case not found.",
        )

    return case


@router.get(
    "/threat-graph/investigation/{investigation_id}"
)
def api_threat_graph(
    investigation_id: str,
):
    reports = load_investigation_reports()

    report = next(
        (
            item
            for item in reports
            if str(
                item.get(
                    "investigation_id"
                )
            ) == investigation_id
        ),
        None,
    )

    if report is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation report not found.",
        )

    return build_threat_graph(report)
