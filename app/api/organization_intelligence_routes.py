from __future__ import annotations

from pathlib import Path

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)
from pydantic import (
    BaseModel,
    Field,
)

from app.organization_intelligence.scoring import (
    identity_score_adjustment,
)
from app.organization_intelligence.store import (
    OrganizationIntelligenceError,
    get_summary,
    import_csv_file,
    initialize_database,
    list_domains,
    resolve_domain,
    upsert_organization_domain,
)


router = APIRouter(
    prefix="/organization-intelligence",
    tags=["Organization Intelligence"],
)


class OrganizationDomainRequest(
    BaseModel
):
    legal_name: str = Field(
        min_length=2,
        max_length=500,
    )

    entity_type: str = "unknown"

    domain: str = Field(
        min_length=3,
        max_length=255,
    )

    source_name: str = Field(
        min_length=2,
        max_length=250,
    )

    source_type: str = "registry"

    source_record_id: str | None = None

    source_url: str | None = None

    authoritative_source: bool = False

    country_code: str | None = None

    jurisdiction: str | None = None

    registration_status: str | None = None

    identity_state: str = "PROVISIONAL"

    security_state: str = "NEUTRAL"

    identity_confidence: float = Field(
        default=50,
        ge=0,
        le=100,
    )

    security_confidence: float = Field(
        default=25,
        ge=0,
        le=100,
    )

    domain_relationship: str = "reported"

    evidence_type: str = (
        "registry_domain_association"
    )

    evidence_value: str | None = None


class ImportRequest(
    BaseModel
):
    csv_path: str


@router.on_event(
    "startup"
)
def initialize_registry() -> None:
    initialize_database()


@router.get("/summary")
def summary():
    return get_summary()


@router.get("/domains")
def domains(
    limit: int = Query(
        default=1000,
        ge=1,
        le=10000,
    ),
):
    return {
        "domains": list_domains(
            limit=limit
        )
    }


@router.get("/resolve")
def resolve(
    hostname: str = Query(
        min_length=3,
    ),
):
    try:
        record = resolve_domain(
            hostname
        )

    except OrganizationIntelligenceError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error

    return {
        "matched": record is not None,
        "record": record,
        "scoring": identity_score_adjustment(
            hostname
        ),
    }


@router.post("/domains")
def save_domain(
    request: OrganizationDomainRequest,
):
    try:
        return upsert_organization_domain(
            **request.model_dump()
        )

    except OrganizationIntelligenceError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error


@router.post("/import")
def import_file(
    request: ImportRequest,
):
    try:
        return import_csv_file(
            Path(
                request.csv_path
            )
        )

    except OrganizationIntelligenceError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error
