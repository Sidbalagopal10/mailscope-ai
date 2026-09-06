from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.reporting.daily_report import (
    DailyReportError,
    create_daily_report,
    load_latest_report,
)


router = APIRouter(
    prefix="/daily-report",
    tags=["Daily Security Report"],
)


@router.post("/generate")
def generate_report():
    try:
        return create_daily_report()

    except DailyReportError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                "Daily report generation failed: "
                f"{error}"
            ),
        ) from error


@router.get("/latest")
def retrieve_latest_report():
    report = load_latest_report()

    if not report:
        return {
            "status": "not_generated",
            "message": (
                "No daily security report "
                "has been generated yet."
            ),
        }

    return report
