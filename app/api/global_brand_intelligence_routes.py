from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.brand_intelligence.global_brand_index import (
    BrandIntelligenceError,
    analyze_brand_impersonation,
    build_global_brand_index,
    get_summary,
    initialize_database,
)


router = APIRouter(
    prefix="/global-brand-intelligence",
    tags=["Global Brand Intelligence"],
)


@router.on_event("startup")
def initialize_brand_database() -> None:
    initialize_database()


@router.get("/summary")
def summary():
    return get_summary()


@router.post("/rebuild")
def rebuild():
    return build_global_brand_index()


@router.get("/analyze")
def analyze(
    domain: str = Query(
        min_length=3,
    ),
):
    try:
        return analyze_brand_impersonation(
            domain
        )

    except BrandIntelligenceError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error
