from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import requests


LOG_PATH = Path(
    "logs/daily_report.log"
)

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


def seconds_until(
    hour: int,
    minute: int,
) -> int:
    now = datetime.now()

    target = now.replace(
        hour=hour,
        minute=minute,
        second=0,
        microsecond=0,
    )

    if target <= now:
        target += timedelta(
            days=1
        )

    return max(
        int(
            (
                target - now
            ).total_seconds()
        ),
        1,
    )


def generate_report(
    api_url: str,
) -> None:
    response = requests.post(
        (
            f"{api_url.rstrip('/')}"
            "/daily-report/generate"
        ),
        timeout=300,
    )

    response.raise_for_status()

    result = response.json()

    logging.info(
        "Daily report generated: %s",
        result.get(
            "report_file"
        ),
    )


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--hour",
        type=int,
        default=19,
    )

    parser.add_argument(
        "--minute",
        type=int,
        default=0,
    )

    parser.add_argument(
        "--api-url",
        default=(
            "http://127.0.0.1:8000"
        ),
    )

    arguments = parser.parse_args()

    if not 0 <= arguments.hour <= 23:
        parser.error(
            "--hour must be from 0 to 23."
        )

    if not 0 <= arguments.minute <= 59:
        parser.error(
            "--minute must be from 0 to 59."
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

    logging.info(
        "Daily report scheduler started."
    )

    logging.info(
        "Scheduled time: %02d:%02d",
        arguments.hour,
        arguments.minute,
    )

    while not shutdown_requested:
        remaining = seconds_until(
            arguments.hour,
            arguments.minute,
        )

        logging.info(
            "Next report in approximately %s seconds.",
            remaining,
        )

        for _ in range(remaining):
            if shutdown_requested:
                break

            time.sleep(1)

        if shutdown_requested:
            break

        try:
            generate_report(
                arguments.api_url
            )

        except Exception:
            logging.exception(
                "Daily report generation failed."
            )

    logging.info(
        "Daily report scheduler stopped."
    )


if __name__ == "__main__":
    main()
