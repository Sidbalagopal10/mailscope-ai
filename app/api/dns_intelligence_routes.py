from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.dns_intelligence.dkim_lookup import (
    check_common_dkim_selectors,
    check_dkim_selector,
)
from app.dns_intelligence.dns_lookup import (
    DNSIntelligenceError,
    get_summary,
    initialize_database,
    list_observations,
    lookup_domain,
)
from app.dns_intelligence.dns_risk import (
    dns_risk_evidence,
)


router = APIRouter(
    prefix="/dns-intelligence",
    tags=["DNS Intelligence"],
)


@router.on_event("startup")
def initialize_dns_database() -> None:
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


@router.get("/lookup")
def lookup(
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

    except DNSIntelligenceError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error

    return {
        "observation": observation,
        "risk_evidence": dns_risk_evidence(
            observation
        ),
    }


@router.get("/dkim")
def dkim_lookup(
    domain: str = Query(
        min_length=3,
    ),
    selector: str | None = None,
):
    try:
        if selector:
            return check_dkim_selector(
                domain,
                selector,
            )

        return check_common_dkim_selectors(
            domain
        )

    except (
        DNSIntelligenceError,
        ValueError,
    ) as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error
