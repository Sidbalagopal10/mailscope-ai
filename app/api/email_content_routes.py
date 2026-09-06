from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.detection.email_content_analyzer import (
    analyze_email_content,
)


router = APIRouter(
    prefix="/email-content",
    tags=["Email Content Analysis"],
)


class EmailContentRequest(BaseModel):
    subject: str = Field(
        default="",
        max_length=500,
    )

    body: str = Field(
        min_length=1,
        max_length=100_000,
    )

    sender: str | None = Field(
        default=None,
        max_length=500,
    )


@router.post("/analyze")
def analyze_email(
    request: EmailContentRequest,
):
    return analyze_email_content(
        subject=request.subject,
        body=request.body,
        sender=request.sender,
    )
