from __future__ import annotations

from fastapi import APIRouter

from app.monitoring.state import (
    get_monitor_summary,
)


router = APIRouter(
    prefix="/monitor",
    tags=["Automatic Gmail Monitor"],
)


@router.get("/summary")
def retrieve_monitor_summary():
    return get_monitor_summary()
