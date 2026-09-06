from __future__ import annotations

import json
from pathlib import Path

from app.reports.models import (
    InvestigationReport,
)


def export_json(
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
        / "report.json"
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
