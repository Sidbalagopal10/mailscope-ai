from __future__ import annotations

import csv
import io
import os
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

from app.benchmarking.models import (
    BenchmarkCase,
)


OUTPUT = Path(
    "data/benchmarking/malicious/"
    "urlhaus_recent.csv"
)


def auth_key() -> str:
    load_dotenv(
        dotenv_path=".env"
    )

    key = str(
        os.getenv(
            "ABUSECH_AUTH_KEY",
            "",
        )
    ).strip()

    if not key:
        raise RuntimeError(
            "ABUSECH_AUTH_KEY is missing from .env."
        )

    return key


def download_urlhaus(
    *,
    force: bool = False,
) -> Path:
    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if (
        OUTPUT.exists()
        and OUTPUT.stat().st_size > 0
        and not force
    ):
        return OUTPUT

    key = auth_key()

    url = (
        "https://urlhaus-api.abuse.ch/"
        "v2/files/exports/"
        f"{key}/recent.csv"
    )

    response = requests.get(
        url,
        timeout=120,
        headers={
            "User-Agent": (
                "AI-Mail-Phishing-Detector/"
                "Benchmarking/1.0"
            ),
        },
    )

    response.raise_for_status()

    OUTPUT.write_bytes(
        response.content
    )

    return OUTPUT


def parse_urlhaus_csv(
    path: Path,
    *,
    limit: int = 5000,
) -> list[BenchmarkCase]:
    text = path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    lines = [
        line
        for line in text.splitlines()
        if line
        and not line.startswith(
            "#"
        )
    ]

    reader = csv.reader(
        io.StringIO(
            "\n".join(
                lines
            )
        )
    )

    cases = []

    for row in reader:
        if len(row) < 3:
            continue

        # URLhaus CSV formats may evolve.
        # Locate the first HTTP(S) field instead
        # of assuming a permanent column index.
        url = None

        for value in row:
            candidate = str(
                value
            ).strip()

            if candidate.lower().startswith(
                (
                    "http://",
                    "https://",
                )
            ):
                url = candidate
                break

        if not url:
            continue

        cases.append(
            BenchmarkCase(
                value=url,
                expected_label="malicious",
                source="urlhaus",
                metadata={
                    "raw_row": row[:8],
                },
            )
        )

        if len(
            cases
        ) >= limit:
            break

    return cases


def load_urlhaus_cases(
    *,
    limit: int = 5000,
) -> list[BenchmarkCase]:
    return parse_urlhaus_csv(
        download_urlhaus(),
        limit=limit,
    )
