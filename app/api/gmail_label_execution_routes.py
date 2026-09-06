from __future__ import annotations

from typing import Any

from fastapi import (
    APIRouter,
    HTTPException,
)
from pydantic import (
    BaseModel,
    Field,
)

from app.gmail_actions.label_executor import (
    GmailLabelExecutionError,
    execute_label_plan,
    undo_execution,
)


router = APIRouter(
    prefix="/gmail-label-execution",
    tags=["Gmail Label Execution"],
)


class ExecuteRequest(BaseModel):
    message_ids: list[str] = Field(
        min_length=1,
        max_length=25,
    )
    confirmation: str
    allow_low_risk: bool = False


class UndoRequest(BaseModel):
    execution_results: list[
        dict[str, Any]
    ]
    confirmation: str


@router.post("/apply")
def apply_labels(
    request: ExecuteRequest,
):
    try:
        return execute_label_plan(
            message_ids=(
                request.message_ids
            ),
            confirmation=(
                request.confirmation
            ),
            allow_low_risk=(
                request.allow_low_risk
            ),
        )

    except GmailLabelExecutionError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error


@router.post("/undo")
def undo_labels(
    request: UndoRequest,
):
    try:
        return undo_execution(
            execution_results=(
                request.execution_results
            ),
            confirmation=(
                request.confirmation
            ),
        )

    except GmailLabelExecutionError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error
