from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.network_intelligence.ip_asn_intelligence import (
    IPASNIntelligenceError,
    get_summary,
    initialize_database,
    list_observations,
    lookup_hostname,
)
from app.network_intelligence.risk import (
    ip_asn_risk_evidence,
)


router = APIRouter(
    prefix="/ip-asn-intelligence",
    tags=["IP and ASN Intelligence"],
)


@router.on_event("startup")
def initialize_network_database() -> None:
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
    hostname: str = Query(
        min_length=3,
    ),
    force: bool = False,
):
    try:
        observation = lookup_hostname(
            hostname,
            force=force,
        )

    except IPASNIntelligenceError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error

    return {
        "observation": observation,
        "risk_evidence": (
            ip_asn_risk_evidence(
                observation
            )
        ),
    }
