from __future__ import annotations

import csv
import io
import zipfile
from pathlib import Path
from typing import Any

import requests

from app.benchmarking.models import (
    BenchmarkCase,
)


TRANCO_LATEST_URL = (
    "https://tranco-list.eu/top-1m.csv.zip"
)

OUTPUT = Path(
    "data/benchmarking/benign/"
    "tranco_top1m.csv.zip"
)


def download_tranco(
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

    response = requests.get(
        TRANCO_LATEST_URL,
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


def load_tranco_cases(
    *,
    limit: int = 5000,
) -> list[BenchmarkCase]:
    path = download_tranco()

    with zipfile.ZipFile(
        path
    ) as archive:
        names = archive.namelist()

        if not names:
            raise RuntimeError(
                "Tranco ZIP is empty."
            )

        raw = archive.read(
            names[0]
        ).decode(
            "utf-8",
            errors="replace",
        )

    reader = csv.reader(
        io.StringIO(
            raw
        )
    )

    cases = []

    for row in reader:
        if len(row) < 2:
            continue

        try:
            rank = int(
                row[0]
            )

        except ValueError:
            continue

        domain = str(
            row[1]
        ).strip()

        if not domain:
            continue

        cases.append(
            BenchmarkCase(
                value=(
                    "https://"
                    + domain
                    + "/"
                ),
                expected_label="benign",
                source="tranco",
                source_rank=rank,
            )
        )

        if len(
            cases
        ) >= limit:
            break

    return cases
