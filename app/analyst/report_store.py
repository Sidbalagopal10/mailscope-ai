from __future__ import annotations

import json
from pathlib import Path

from app.analyst.report_schema import (
    AnalystReport,
)


REPORT_DIRECTORY = Path(
    "data/investigations/reports"
)


def save_report(
    report: AnalystReport,
) -> Path:
    REPORT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = (
        REPORT_DIRECTORY
        / (
            report.investigation_id
            + ".json"
        )
    )

    path.write_text(
        json.dumps(
            report.to_dict(),
            indent=2,
            sort_keys=True,
            default=str,
        ),
        encoding="utf-8",
    )

    return path
