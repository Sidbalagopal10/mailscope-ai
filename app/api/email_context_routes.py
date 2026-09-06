from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from app.email_authentication.header_parser import (
    parse_email_authentication,
)
from app.email_security.contextual_decision import (
    contextual_email_decision,
)


router = APIRouter(
    prefix="/email-context",
    tags=["Email Context"],
)


class HeaderItem(BaseModel):
    name: str
    value: str


class EmailContextRequest(BaseModel):
    subject: str = ""
    body: str = ""
    headers: list[HeaderItem] = []
    link_risk_score: float = 0.0
    attachment_risk_score: float = 0.0
    known_sender: bool = False
    existing_thread: bool = False
    sender_domain_verified: bool = False


@router.post("/analyze")
def analyze(
    request: EmailContextRequest,
) -> dict[str, Any]:
    authentication = (
        parse_email_authentication(
            [
                item.model_dump()
                for item in request.headers
            ]
        )
    )

    return contextual_email_decision(
        subject=request.subject,
        body=request.body,
        authentication=authentication,
        link_risk_score=(
            request.link_risk_score
        ),
        attachment_risk_score=(
            request.attachment_risk_score
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
    )
