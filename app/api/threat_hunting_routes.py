from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.threat_hunting.engine import (
    hunt_reports,
)


router = APIRouter(
    prefix="/threat-hunts",
    tags=["Threat Hunting"],
)


@router.get("/search")
def search_historical_investigations(
    query: str = Query(
        min_length=1
    ),
    observable_type: (
        str | None
    ) = Query(
        default=None
    ),
):
    try:
        result = hunt_reports(
            query=query,
            observable_type=(
                observable_type
            ),
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(
                error
            ),
        ) from error

    return result.to_dict()
