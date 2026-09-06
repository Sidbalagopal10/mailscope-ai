from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.domain_intelligence.rdap_client import (
    RdapLookupError,
    get_summary,
    initialize_database,
    list_observations,
    lookup_domain,
)
from app.domain_intelligence.risk import (
    rdap_risk_evidence,
)


router = APIRouter(
    prefix="/domain-intelligence",
    tags=["Domain Intelligence"],
)


@router.on_event("startup")
def initialize_domain_intelligence() -> None:
    initialize_database()


@router.get("/summary")
def summary():
    return get_summary()


@router.get("/observations")
def observations(
    limit: int = Query(
        default=500,
        ge=1,
        le=5000,
    ),
):
    return {
        "observations": list_observations(
            limit=limit
        )
    }


@router.get("/rdap")
def rdap_lookup(
    domain: str = Query(
        min_length=3,
    ),
    force: bool = False,
):
    try:
        observation = lookup_domain(
            domain,
            force=force,
        )

    except RdapLookupError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error

    return {
        "observation": observation,
        "risk_evidence": rdap_risk_evidence(
            observation
        ),
    }
