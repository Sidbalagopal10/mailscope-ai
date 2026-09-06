from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.email_security.header_analyzer import analyze_email_headers
from app.gmail.gmail_client import get_gmail_service


router = APIRouter(
    prefix="/header-analysis",
    tags=["Email Header Analysis"],
)


def find_header(headers: list[dict], name: str) -> str:
    for header in headers:
        if str(header.get("name", "")).lower() == name.lower():
            return str(header.get("value", ""))

    return ""


def fetch_metadata(service, message_id: str) -> dict:
    return (
        service.users()
        .messages()
        .get(
            userId="me",
            id=message_id,
            format="metadata",
            metadataHeaders=[
                "From",
                "Reply-To",
                "Return-Path",
                "Authentication-Results",
                "Received-SPF",
                "Message-ID",
                "Subject",
                "Date",
            ],
        )
        .execute()
    )


@router.get("/gmail-message")
def analyze_gmail_message_headers(
    gmail_message_id: str = Query(..., min_length=1),
):
    try:
        service = get_gmail_service()
        message = fetch_metadata(service, gmail_message_id)
        headers = message.get("payload", {}).get("headers", [])

        return {
            "gmail_message_id": gmail_message_id,
            "subject": find_header(headers, "Subject"),
            **analyze_email_headers(headers),
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Email-header analysis failed: {error}",
        ) from error


@router.get("/recent")
def analyze_recent_headers(
    limit: int = Query(default=10, ge=1, le=50),
):
    try:
        service = get_gmail_service()

        response = (
            service.users()
            .messages()
            .list(
                userId="me",
                maxResults=limit,
            )
            .execute()
        )

        results = []

        for reference in response.get("messages", []):
            message_id = reference["id"]
            message = fetch_metadata(service, message_id)
            headers = message.get("payload", {}).get("headers", [])

            results.append(
                {
                    "gmail_message_id": message_id,
                    "subject": find_header(headers, "Subject"),
                    **analyze_email_headers(headers),
                }
            )

        return {
            "emails_analyzed": len(results),
            "suspicious_emails": sum(
                1 for result in results
                if result["is_suspicious"]
            ),
            "results": results,
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Recent header analysis failed: {error}",
        ) from error
