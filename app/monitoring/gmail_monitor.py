from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from pathlib import Path

from app.email_security.full_email_analyzer import (
    analyze_gmail_message,
)
from app.email_security.storage import (
    save_email_analysis,
)
from app.gmail.gmail_client import (
    get_gmail_service,
)
from app.gmail.label_service import (
    apply_risk_label,
    ensure_risk_labels,
)
from app.monitoring.state import (
    initialize_database,
    message_was_processed,
    save_processed_message,
)


LOG_PATH = Path("logs/gmail_monitor.log")

shutdown_requested = False


def configure_logging() -> None:
    LOG_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s | %(levelname)s | %(message)s"
        ),
        handlers=[
            logging.FileHandler(
                LOG_PATH,
                encoding="utf-8",
            ),
            logging.StreamHandler(
                sys.stdout
            ),
        ],
    )


def handle_shutdown(
    signum,
    frame,
) -> None:
    global shutdown_requested

    shutdown_requested = True

    logging.info(
        "Shutdown requested. Monitor will stop safely."
    )


def fetch_recent_message_ids(
    service,
    limit: int,
) -> list[str]:
    response = (
        service.users()
        .messages()
        .list(
            userId="me",
            maxResults=limit,
            q="in:anywhere newer_than:7d",
        )
        .execute()
    )

    return [
        item["id"]
        for item in response.get(
            "messages",
            [],
        )
        if item.get("id")
    ]


def process_message(
    *,
    service,
    gmail_message_id: str,
) -> dict:
    message = (
        service.users()
        .messages()
        .get(
            userId="me",
            id=gmail_message_id,
            format="full",
        )
        .execute()
    )

    analysis = analyze_gmail_message(
        message
    )

    save_email_analysis(
        analysis
    )

    label_result = apply_risk_label(
        service=service,
        gmail_message_id=gmail_message_id,
        risk_level=analysis[
            "risk_level"
        ],
    )

    save_processed_message(
        gmail_message_id=gmail_message_id,
        status="completed",
        risk_level=analysis[
            "risk_level"
        ],
        combined_score=float(
            analysis["combined_score"]
        ),
    )

    return {
        "gmail_message_id": gmail_message_id,
        "subject": analysis.get(
            "subject"
        ),
        "sender": analysis.get(
            "sender"
        ),
        "risk_level": analysis.get(
            "risk_level"
        ),
        "combined_score": analysis.get(
            "combined_score"
        ),
        "label_name": label_result.get(
            "label_name"
        ),
    }


def scan_once(
    *,
    service,
    fetch_limit: int,
) -> dict:
    message_ids = fetch_recent_message_ids(
        service,
        fetch_limit,
    )

    new_messages = 0
    completed = 0
    failed = 0

    for gmail_message_id in reversed(
        message_ids
    ):
        if shutdown_requested:
            break

        if message_was_processed(
            gmail_message_id
        ):
            continue

        new_messages += 1

        logging.info(
            "Analyzing Gmail message %s",
            gmail_message_id,
        )

        try:
            result = process_message(
                service=service,
                gmail_message_id=gmail_message_id,
            )

            completed += 1

            logging.info(
                "Completed | %s | score=%s | subject=%s",
                result["risk_level"],
                result["combined_score"],
                result["subject"],
            )

        except Exception as error:
            failed += 1

            save_processed_message(
                gmail_message_id=gmail_message_id,
                status="failed",
                error_message=str(error),
            )

            logging.exception(
                "Failed to process Gmail message %s",
                gmail_message_id,
            )

    return {
        "messages_checked": len(
            message_ids
        ),
        "new_messages": new_messages,
        "completed": completed,
        "failed": failed,
    }


def run_monitor(
    *,
    interval_seconds: int,
    fetch_limit: int,
) -> None:
    initialize_database()

    logging.info(
        "Connecting to Gmail..."
    )

    service = get_gmail_service()

    ensure_risk_labels(
        service
    )

    logging.info(
        "Automatic Gmail monitor started."
    )

    logging.info(
        "Polling interval: %s seconds",
        interval_seconds,
    )

    logging.info(
        "Messages checked per cycle: %s",
        fetch_limit,
    )

    while not shutdown_requested:
        cycle_started = time.time()

        try:
            summary = scan_once(
                service=service,
                fetch_limit=fetch_limit,
            )

            logging.info(
                "Cycle complete | checked=%s | "
                "new=%s | completed=%s | failed=%s",
                summary["messages_checked"],
                summary["new_messages"],
                summary["completed"],
                summary["failed"],
            )

        except Exception:
            logging.exception(
                "Automatic Gmail monitoring cycle failed."
            )

            try:
                service = get_gmail_service()
            except Exception:
                logging.exception(
                    "Unable to reconnect to Gmail."
                )

        elapsed = time.time() - cycle_started

        remaining = max(
            1,
            interval_seconds - int(elapsed),
        )

        for _ in range(remaining):
            if shutdown_requested:
                break

            time.sleep(1)

    logging.info(
        "Automatic Gmail monitor stopped."
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Automatically scan new Gmail messages "
            "and apply phishing-risk labels."
        )
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=300,
        help=(
            "Polling interval in seconds. "
            "Default: 300 seconds."
        ),
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=25,
        help=(
            "Maximum recent Gmail messages checked "
            "during each cycle."
        ),
    )

    arguments = parser.parse_args()

    if arguments.interval < 60:
        parser.error(
            "--interval must be at least 60 seconds."
        )

    if arguments.limit < 1:
        parser.error(
            "--limit must be at least 1."
        )

    configure_logging()

    signal.signal(
        signal.SIGINT,
        handle_shutdown,
    )

    signal.signal(
        signal.SIGTERM,
        handle_shutdown,
    )

    run_monitor(
        interval_seconds=arguments.interval,
        fetch_limit=min(
            arguments.limit,
            100,
        ),
    )


if __name__ == "__main__":
    main()
