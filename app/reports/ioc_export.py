from __future__ import annotations

import csv
from pathlib import Path

from app.reports.models import (
    InvestigationReport,
)


def export_ioc_csv(
    report: InvestigationReport,
    *,
    directory: Path,
) -> Path:
    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = (
        directory
        / "indicators.csv"
    )

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.writer(
            handle
        )

        writer.writerow(
            [
                "type",
                "value",
                "source",
                "confidence",
            ]
        )

        for ioc in report.iocs:
            writer.writerow(
                [
                    ioc.type,
                    ioc.value,
                    ioc.source,
                    ioc.confidence,
                ]
            )

    return path
