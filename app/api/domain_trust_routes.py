from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)
from pydantic import BaseModel, Field

from app.trust.domain_store import (
    DomainTrustError,
    delete_domain,
    list_domains,
    seed_recommended_domains,
    upsert_domain,
)


router = APIRouter(
    prefix="/domain-trust",
    tags=["Trusted Domain Intelligence"],
)


class DomainTrustRequest(BaseModel):
    domain: str = Field(
        min_length=3,
        max_length=255,
    )

    status: str = Field(
        default="TRUSTED",
    )

    category: str | None = Field(
        default=None,
        max_length=100,
    )

    notes: str | None = Field(
        default=None,
        max_length=1000,
    )


@router.get("")
def retrieve_domains(
    status: str | None = Query(
        default=None,
    ),
):
    try:
        return {
            "domains": list_domains(
                status=status
            )
        }

    except DomainTrustError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error


@router.post("")
def save_domain(
    request: DomainTrustRequest,
):
    try:
        return upsert_domain(
            domain=request.domain,
            status=request.status,
            category=request.category,
            notes=request.notes,
        )

    except DomainTrustError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error


@router.post("/seed-recommended")
def seed_domains():
    return {
        "status": "completed",
        "records_processed": (
            seed_recommended_domains()
        ),
    }


@router.delete("/{domain_id}")
def remove_domain(
    domain_id: int,
):
    deleted = delete_domain(
        domain_id
    )

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Domain record was not found.",
        )

    return {
        "status": "deleted",
        "id": domain_id,
    }
