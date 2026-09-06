from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.gmail_observation.observer import (
    GmailObservationError,
    observe_recent_messages,
    save_observation_report,
)


router = APIRouter(
    prefix="/gmail-observation",
    tags=["Gmail Observation"],
)


@router.get("/recent")
def recent(
    max_results: int = Query(
        default=10,
        ge=1,
        le=25,
    ),
    query: str = Query(
        default="in:inbox newer_than:14d",
        min_length=1,
    ),
):
    try:
        report = observe_recent_messages(
            max_results=max_results,
            query=query,
        )

        path = save_observation_report(
            report
        )

        return {
            **report,
            "saved_report": str(
                path
            ),
        }

    except GmailObservationError as error:
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
