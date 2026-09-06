from __future__ import annotations

import json
from pathlib import Path

from fastapi import (
    APIRouter,
    HTTPException,
)

from app.gmail_actions.label_planner import (
    build_label_plan,
    save_label_plan,
)


router = APIRouter(
    prefix="/gmail-label-plan",
    tags=["Gmail Label Plan"],
)


OBSERVATION_PATH = Path(
    "data/gmail_observation/latest_observation.json"
)


@router.get("/latest")
def latest():
    if not OBSERVATION_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                "No Gmail observation report exists. "
                "Run Gmail Observation Mode first."
            ),
        )

    try:
        observation = json.loads(
            OBSERVATION_PATH.read_text(
                encoding="utf-8"
            )
        )

    except json.JSONDecodeError as error:
        raise HTTPException(
            status_code=500,
            detail=(
                "The latest Gmail observation report "
                "contains invalid JSON."
            ),
        ) from error

    plan = build_label_plan(
        observation
    )

    path = save_label_plan(
        plan
    )

    return {
        **plan,
        "saved_report": str(
            path
        ),
    }
