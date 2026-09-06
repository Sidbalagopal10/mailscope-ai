from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.domain_intelligence.safe_unified_profile import (
    analyze_unified_domain_profile,
)


router = APIRouter(
    prefix="/unified-domain-profile",
    tags=["Unified Domain Profile"],
)


@router.get("/analyze")
def analyze(
    value: str = Query(
        min_length=3,
    ),
    force_refresh: bool = False,
    include_ct_subdomains: bool = False,
):
    try:
        return analyze_unified_domain_profile(
            value,
            force_refresh=force_refresh,
            include_ct_subdomains=(
                include_ct_subdomains
            ),
        )

    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error

    except RuntimeError as error:
        raise HTTPException(
            status_code=500,
            detail=str(
                error
            ),
        ) from error
