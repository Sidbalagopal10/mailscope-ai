from __future__ import annotations

from fastapi import (
    APIRouter,
    Query,
)

from app.global_entity_registry.identity.explanation import (
    explain_identity,
)


router = APIRouter(
    prefix="/identity",
    tags=[
        "identity-intelligence",
    ],
)


@router.get(
    "/explain"
)
def explain_identity_route(
    value: str = Query(
        ...,
        min_length=1,
        description=(
            "URL, hostname or domain to explain."
        ),
    )
):
    return explain_identity(
        value
    )


@router.get(
    "/confidence"
)
def identity_confidence_route(
    domain: str = Query(
        ...,
        min_length=1,
    )
):
    result = explain_identity(
        domain
    )

    return {
        "input": (
            domain
        ),

        "canonical_domain": (
            result[
                "canonical_domain"
            ]
        ),

        "identity_known": (
            result[
                "identity_known"
            ]
        ),

        "best_match": (
            result[
                "best_match"
            ]
        ),
    }
