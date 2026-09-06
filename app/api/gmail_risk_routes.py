from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.email_security.full_email_analyzer import (
    analyze_gmail_message,
)
from app.email_security.storage import (
    get_summary,
    initialize_database,
    list_email_analyses,
    save_email_analysis,
)
from app.gmail.gmail_client import (
    get_gmail_service,
)
from app.gmail.label_service import (
    apply_risk_label,
    ensure_risk_labels,
)


router = APIRouter(
    prefix="/gmail-risk",
    tags=["Combined Gmail Risk"],
)


@router.post("/setup-labels")
def setup_gmail_risk_labels():
    try:
        service = get_gmail_service()

        labels = ensure_risk_labels(
            service
        )

        return {
            "status": "completed",
            "message": (
                "Gmail risk labels are ready."
            ),
            "labels": labels,
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to prepare Gmail labels: "
                f"{error}"
            ),
        ) from error


@router.post("/scan")
def scan_recent_gmail(
    limit: int = Query(
        default=5,
        ge=1,
        le=25,
    ),
    apply_labels: bool = Query(
        default=True,
        description=(
            "Apply the calculated AI Security "
            "risk label inside Gmail."
        ),
    ),
):
    initialize_database()

    try:
        service = get_gmail_service()

        if apply_labels:
            ensure_risk_labels(
                service
            )

        response = (
            service.users()
            .messages()
            .list(
                userId="me",
                maxResults=limit,
            )
            .execute()
        )

        messages = response.get(
            "messages",
            [],
        )

        saved_results = []
        label_results = []
        label_errors = []

        for reference in messages:
            message = (
                service.users()
                .messages()
                .get(
                    userId="me",
                    id=reference["id"],
                    format="full",
                )
                .execute()
            )

            analysis = analyze_gmail_message(
                message
            )

            saved_record = save_email_analysis(
                analysis
            )

            saved_results.append(
                saved_record
            )

            if apply_labels:
                try:
                    label_result = apply_risk_label(
                        service=service,
                        gmail_message_id=reference["id"],
                        risk_level=analysis[
                            "risk_level"
                        ],
                    )

                    label_results.append(
                        label_result
                    )

                except Exception as label_error:
                    label_errors.append(
                        {
                            "gmail_message_id": (
                                reference["id"]
                            ),
                            "error": str(
                                label_error
                            ),
                        }
                    )

        return {
            "status": "completed",
            "emails_requested": limit,
            "emails_scanned": len(
                saved_results
            ),
            "suspicious_emails": sum(
                1
                for result in saved_results
                if result["is_suspicious"]
            ),
            "phishing_emails": sum(
                1
                for result in saved_results
                if result["is_phishing"]
            ),
            "labels_enabled": apply_labels,
            "labels_applied": len(
                label_results
            ),
            "label_errors": label_errors,
            "results": saved_results,
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                "Combined Gmail scan failed: "
                f"{error}"
            ),
        ) from error


@router.get("/history")
def retrieve_history(
    limit: int = Query(
        default=200,
        ge=1,
        le=1000,
    ),
):
    return list_email_analyses(
        limit=limit
    )


@router.get("/summary")
def retrieve_summary():
    return get_summary()
