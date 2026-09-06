from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)
from pydantic import BaseModel

from app.gmail_feedback.review_store import (
    GmailFeedbackError,
    get_summary,
    list_reviews,
    save_review,
)


router = APIRouter(
    prefix="/gmail-feedback",
    tags=["Gmail Feedback"],
)


PLAN_PATH = Path(
    "data/gmail_actions/latest_label_plan.json"
)


class ReviewRequest(BaseModel):
    message_id: str
    review_verdict: str
    reviewer_notes: str | None = None


def load_plan_items() -> dict[str, dict[str, Any]]:
    if not PLAN_PATH.exists():
        raise GmailFeedbackError(
            "No Gmail label plan exists. Run observation "
            "and dry-run planning first."
        )

    try:
        plan = json.loads(
            PLAN_PATH.read_text(
                encoding="utf-8"
            )
        )

    except json.JSONDecodeError as error:
        raise GmailFeedbackError(
            "The saved Gmail label plan contains invalid JSON."
        ) from error

    return {
        str(
            item.get(
                "message_id"
            )
        ): item
        for item in plan.get(
            "plans",
            []
        )
        if item.get(
            "message_id"
        )
    }


@router.get("/candidates")
def candidates():
    try:
        items = load_plan_items()

    except GmailFeedbackError as error:
        raise HTTPException(
            status_code=404,
            detail=str(
                error
            ),
        ) from error

    return {
        "candidates": list(
            items.values()
        )
    }


@router.post("/review")
def review(
    request: ReviewRequest,
):
    try:
        items = load_plan_items()

        item = items.get(
            request.message_id
        )

        if item is None:
            raise GmailFeedbackError(
                "The selected message is absent from "
                "the latest label plan."
            )

        return save_review(
            message_id=request.message_id,
            thread_id=item.get(
                "thread_id"
            ),
            subject=item.get(
                "subject"
            ),
            sender_address=item.get(
                "sender_address"
            ),
            predicted_score=float(
                item.get(
                    "risk_score",
                    0,
                )
                or 0
            ),
            predicted_risk_level=str(
                item.get(
                    "risk_level",
                    "low",
                )
            ),
            predicted_classification=(
                item.get(
                    "classification"
                )
            ),
            proposed_labels=list(
                item.get(
                    "proposed_labels",
                    [],
                )
            ),
            review_verdict=(
                request.review_verdict
            ),
            reviewer_notes=(
                request.reviewer_notes
            ),
        )

    except GmailFeedbackError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error


@router.get("/reviews")
def reviews(
    limit: int = Query(
        default=500,
        ge=1,
        le=5000,
    ),
):
    return {
        "reviews": list_reviews(
            limit=limit
        )
    }


@router.get("/summary")
def summary():
    return get_summary()
