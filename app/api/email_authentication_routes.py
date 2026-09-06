from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from app.email_authentication.header_parser import (
    parse_email_authentication,
)
from app.email_authentication.risk import (
    authentication_risk_evidence,
)


router = APIRouter(
    prefix="/email-authentication",
    tags=["Email Authentication"],
)


class HeaderItem(BaseModel):
    name: str
    value: str


class AuthenticationRequest(BaseModel):
    headers: list[HeaderItem]


@router.post("/analyze")
def analyze(
    request: AuthenticationRequest,
) -> dict[str, Any]:
    headers = [
        item.model_dump()
        for item in request.headers
    ]

    authentication = (
        parse_email_authentication(
            headers
        )
    )

    return {
        "authentication": authentication,
        "risk_evidence": (
            authentication_risk_evidence(
                authentication
            )
        ),
    }
