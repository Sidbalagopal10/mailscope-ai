from __future__ import annotations

import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import requests


API_BASE_URL = "http://127.0.0.1:8000"

REPORT_DIRECTORY = Path("reports/daily")


class DailyReportError(Exception):
    pass


def api_get(
    endpoint: str,
    timeout: int = 30,
) -> Any:
    response = requests.get(
        f"{API_BASE_URL}{endpoint}",
        timeout=timeout,
    )

    response.raise_for_status()
    return response.json()


def safe_api_get(
    endpoint: str,
    default: Any,
) -> Any:
    try:
        return api_get(endpoint)
    except requests.RequestException:
        return default


def risk_rank(
    risk_level: str,
) -> int:
    order = {
        "LOW": 0,
        "GUARDED": 1,
        "MODERATE": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    return order.get(
        str(risk_level or "").upper(),
        -1,
    )


def create_daily_report() -> dict[str, Any]:
    generated_at = datetime.now(
        timezone.utc
    ).isoformat()

    gmail_summary = safe_api_get(
        "/gmail-risk/summary",
        {},
    )

    gmail_history = safe_api_get(
        "/gmail-risk/history?limit=500",
        [],
    )

    feedback_summary = safe_api_get(
        "/feedback/summary",
        {},
    )

    monitor_summary = safe_api_get(
        "/monitor/summary",
        {},
    )

    dashboard_summary = safe_api_get(
        "/dashboard-summary",
        {},
    )

    suspicious_messages = [
        record
        for record in gmail_history
        if bool(
            record.get(
                "is_suspicious",
                False,
            )
        )
    ]

    suspicious_messages.sort(
        key=lambda record: (
            risk_rank(
                record.get(
                    "risk_level",
                    "",
                )
            ),
            float(
                record.get(
                    "combined_score",
                    0,
                )
                or 0
            ),
        ),
        reverse=True,
    )

    top_messages = []

    for record in suspicious_messages[:10]:
        analysis = record.get(
            "analysis",
            {},
        )

        attachment_analysis = analysis.get(
            "attachment_analysis",
            {},
        )

        top_messages.append(
            {
                "gmail_message_id": record.get(
                    "gmail_message_id"
                ),
                "subject": record.get(
                    "subject"
                ),
                "sender": record.get(
                    "sender"
                ),
                "risk_level": record.get(
                    "risk_level"
                ),
                "combined_score": record.get(
                    "combined_score",
                    0,
                ),
                "content_score": record.get(
                    "content_score",
                    0,
                ),
                "highest_url_score": record.get(
                    "highest_url_score",
                    0,
                ),
                "header_score": analysis.get(
                    "header_score",
                    0,
                ),
                "attachment_score": analysis.get(
                    "attachment_score",
                    0,
                ),
                "link_count": record.get(
                    "link_count",
                    0,
                ),
                "attachment_count": (
                    attachment_analysis.get(
                        "attachment_count",
                        0,
                    )
                ),
                "recommendation": record.get(
                    "recommendation"
                ),
            }
        )

    report = {
        "report_date": date.today().isoformat(),
        "generated_at": generated_at,
        "email_security": {
            "emails_analyzed": int(
                gmail_summary.get(
                    "total_emails",
                    0,
                )
                or 0
            ),
            "suspicious_emails": int(
                gmail_summary.get(
                    "suspicious_emails",
                    0,
                )
                or 0
            ),
            "likely_phishing_emails": int(
                gmail_summary.get(
                    "phishing_emails",
                    0,
                )
                or 0
            ),
            "average_risk_score": float(
                gmail_summary.get(
                    "average_score",
                    0,
                )
                or 0
            ),
            "highest_risk_score": float(
                gmail_summary.get(
                    "highest_score",
                    0,
                )
                or 0
            ),
            "total_links": int(
                gmail_summary.get(
                    "total_links",
                    0,
                )
                or 0
            ),
            "suspicious_urls": int(
                gmail_summary.get(
                    "suspicious_urls",
                    0,
                )
                or 0
            ),
            "risk_distribution": (
                gmail_summary.get(
                    "risk_distribution",
                    {},
                )
            ),
        },
        "feedback": {
            "total_feedback": int(
                feedback_summary.get(
                    "total_feedback",
                    0,
                )
                or 0
            ),
            "correct_predictions": int(
                feedback_summary.get(
                    "correct_predictions",
                    0,
                )
                or 0
            ),
            "incorrect_predictions": int(
                feedback_summary.get(
                    "incorrect_predictions",
                    0,
                )
                or 0
            ),
            "verified_accuracy": float(
                feedback_summary.get(
                    "verified_accuracy",
                    0,
                )
                or 0
            ),
            "confusion_matrix": (
                feedback_summary.get(
                    "confusion_matrix",
                    {},
                )
            ),
        },
        "automatic_monitor": {
            "total_processed": int(
                monitor_summary.get(
                    "total_processed",
                    0,
                )
                or 0
            ),
            "completed": int(
                monitor_summary.get(
                    "completed",
                    0,
                )
                or 0
            ),
            "failed": int(
                monitor_summary.get(
                    "failed",
                    0,
                )
                or 0
            ),
            "last_activity": (
                monitor_summary.get(
                    "last_activity"
                )
            ),
        },
        "legacy_dashboard": dashboard_summary,
        "top_risk_messages": top_messages,
    }

    REPORT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    dated_path = (
        REPORT_DIRECTORY
        / f"{report['report_date']}.json"
    )

    latest_path = (
        REPORT_DIRECTORY
        / "latest.json"
    )

    serialized = json.dumps(
        report,
        indent=2,
        ensure_ascii=False,
        default=str,
    )

    dated_path.write_text(
        serialized,
        encoding="utf-8",
    )

    latest_path.write_text(
        serialized,
        encoding="utf-8",
    )

    report["report_file"] = str(
        dated_path
    )

    return report


def load_latest_report() -> dict[str, Any]:
    latest_path = (
        REPORT_DIRECTORY
        / "latest.json"
    )

    if not latest_path.exists():
        return {}

    try:
        return json.loads(
            latest_path.read_text(
                encoding="utf-8"
            )
        )
    except json.JSONDecodeError:
        return {}
