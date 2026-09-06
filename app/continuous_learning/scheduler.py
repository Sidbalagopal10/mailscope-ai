from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from pathlib import Path

import requests


LOG_PATH = Path(
    "logs/continuous_learning.log"
)

shutdown_requested = False


def handle_shutdown(
    signum,
    frame,
) -> None:
    global shutdown_requested
    shutdown_requested = True


def configure_logging() -> None:
    LOG_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s | "
            "%(levelname)s | "
            "%(message)s"
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


def request_retraining(
    api_url: str,
) -> None:
    response = requests.post(
        (
            f"{api_url.rstrip('/')}"
            "/continuous-learning/retrain"
        ),
        timeout=7200,
    )

    response.raise_for_status()

    logging.info(
        "Retraining response: %s",
        response.json(),
    )


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--interval",
        type=int,
        default=86400,
    )

    parser.add_argument(
        "--api-url",
        default=(
            "http://127.0.0.1:8000"
        ),
    )

    arguments = parser.parse_args()

    if arguments.interval < 3600:
        parser.error(
            "Interval must be at least "
            "one hour."
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
        "Continuous-learning scheduler started."
    )

    while not shutdown_requested:
        try:
            request_retraining(
                arguments.api_url
            )

        except Exception:
            logging.exception(
                "Scheduled retraining failed."
            )

        for _ in range(
            arguments.interval
        ):
            if shutdown_requested:
                break

            time.sleep(1)

    logging.info(
        "Continuous-learning scheduler stopped."
    )


if __name__ == "__main__":
    main()
