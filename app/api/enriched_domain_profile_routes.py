from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.domain_intelligence.enriched_profile import (
    analyze_enriched_domain_profile,
)


router = APIRouter(
    prefix="/enriched-domain-profile",
    tags=["Enriched Domain Profile"],
)


@router.get("/analyze")
def analyze(
    value: str = Query(
        min_length=3,
    ),
    force_refresh: bool = False,
    include_ct_subdomains: bool = False,
    enable_virustotal: bool = True,
):
    try:
        return analyze_enriched_domain_profile(
            value,
            force_refresh=force_refresh,
            include_ct_subdomains=(
                include_ct_subdomains
            ),
            enable_virustotal=(
                enable_virustotal
            ),
        )

    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(
                error
            ),
        ) from error
