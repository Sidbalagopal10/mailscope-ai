from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.domain_intelligence.certificate_transparency import (
    CertificateTransparencyError,
    get_global_summary,
    initialize_database,
    list_summaries,
    lookup_domain,
)
from app.domain_intelligence.ct_risk import (
    certificate_transparency_evidence,
)


router = APIRouter(
    prefix="/certificate-transparency",
    tags=["Certificate Transparency"],
)


@router.on_event("startup")
def initialize_ct_database() -> None:
    initialize_database()


@router.get("/summary")
def summary():
    return get_global_summary()


@router.get("/observations")
def observations(
    limit: int = Query(
        default=500,
        ge=1,
        le=5000,
    ),
):
    return {
        "observations": list_summaries(
            limit=limit
        )
    }


@router.get("/lookup")
def lookup(
    domain: str = Query(
        min_length=3,
    ),
    include_subdomains: bool = True,
    force: bool = False,
):
    try:
        result = lookup_domain(
            domain,
            include_subdomains=(
                include_subdomains
            ),
            force=force,
        )

    except CertificateTransparencyError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error

    return {
        "observation": result,
        "risk_evidence": (
            certificate_transparency_evidence(
                result
            )
        ),
    }
