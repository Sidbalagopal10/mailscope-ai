from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.threat_intelligence.threatfox_client import (
    ThreatFoxError,
    get_summary,
    initialize_database,
    list_observations,
    lookup_indicator,
)
from app.threat_intelligence.threatfox_risk import (
    threatfox_risk_evidence,
)


router = APIRouter(
    prefix="/threatfox",
    tags=["ThreatFox Intelligence"],
)


@router.on_event("startup")
def initialize_threatfox_database() -> None:
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
    indicator: str = Query(
        min_length=3,
    ),
    force: bool = False,
):
    try:
        observation = lookup_indicator(
            indicator,
            force=force,
        )

    except ThreatFoxError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error

    return {
        "observation": observation,
        "risk_evidence": (
            threatfox_risk_evidence(
                observation
            )
        ),
    }
