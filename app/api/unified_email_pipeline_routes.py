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

from app.email_pipeline.unified_pipeline import (
    analyze_email_security_pipeline,
)


router = APIRouter(
    prefix="/email-security-pipeline",
    tags=["Unified Email Security Pipeline"],
)


class HeaderItem(BaseModel):
    name: str
    value: str


class UnifiedEmailRequest(BaseModel):
    subject: str = ""
    body: str = ""
    headers: list[HeaderItem] = Field(
        default_factory=list
    )
    urls: list[str] = Field(
        default_factory=list
    )
    message_id: str | None = None
    thread_id: str | None = None
    sender_address: str | None = None
    known_sender: bool = False
    existing_thread: bool = False
    sender_domain_verified: bool = False
    attachment_risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )
    maximum_deep_urls: int = Field(
        default=5,
        ge=1,
        le=10,
    )
    force_refresh: bool = False
    enable_virustotal: bool = True


@router.post("/analyze")
def analyze(
    request: UnifiedEmailRequest,
) -> dict[str, Any]:
    try:
        return analyze_email_security_pipeline(
            subject=request.subject,
            body=request.body,
            headers=[
                item.model_dump()
                for item in request.headers
            ],
            urls=request.urls,
            message_id=(
                request.message_id
            ),
            thread_id=(
                request.thread_id
            ),
            sender_address=(
                request.sender_address
            ),
            known_sender=(
                request.known_sender
            ),
            existing_thread=(
                request.existing_thread
            ),
            sender_domain_verified=(
                request.sender_domain_verified
            ),
            attachment_risk_score=(
                request.attachment_risk_score
            ),
            maximum_deep_urls=(
                request.maximum_deep_urls
            ),
            force_refresh=(
                request.force_refresh
            ),
            enable_virustotal=(
                request.enable_virustotal
            ),
        )

    except ValueError as error:
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
