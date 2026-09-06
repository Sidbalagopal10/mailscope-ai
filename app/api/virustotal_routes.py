from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.threat_intelligence.virustotal_client import (
    VirusTotalError,
    get_summary,
    initialize_database,
    list_observations,
    lookup_indicator,
    lookup_url_and_domain,
)
from app.threat_intelligence.virustotal_risk import (
    combine_virustotal_evidence,
    virustotal_risk_evidence,
)


router = APIRouter(
    prefix="/virustotal",
    tags=["VirusTotal Intelligence"],
)


@router.on_event("startup")
def initialize_virustotal_database() -> None:
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

    except VirusTotalError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error

    return {
        "observation": observation,
        "risk_evidence": (
            virustotal_risk_evidence(
                observation
            )
        ),
    }


@router.get("/lookup-url")
def lookup_url(
    url: str = Query(
        min_length=8,
    ),
    force: bool = False,
):
    try:
        lookup_result = lookup_url_and_domain(
            url,
            force=force,
        )

    except VirusTotalError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error

    return {
        "lookup": lookup_result,
        "combined_evidence": (
            combine_virustotal_evidence(
                lookup_result
            )
        ),
    }
