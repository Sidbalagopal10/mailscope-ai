from __future__ import annotations

from pathlib import Path

from app.reports.ioc_export import (
    export_ioc_csv,
)
from app.reports.json_export import (
    export_json,
)
from app.reports.markdown_export import (
    export_markdown,
)
from app.reports.models import (
    InvestigationReport,
)


REPORT_ROOT = Path(
    "data/investigations/reports"
)


def export_report_bundle(
    report: InvestigationReport,
) -> dict[str, str]:
    directory = (
        REPORT_ROOT
        / report.investigation_id
    )

    json_path = export_json(
        report,
        directory=directory,
    )

    markdown_path = export_markdown(
        report,
        directory=directory,
    )

    ioc_path = export_ioc_csv(
        report,
        directory=directory,
    )

    return {
        "directory": str(
            directory
        ),

        "json": str(
            json_path
        ),

        "markdown": str(
            markdown_path
        ),

        "iocs": str(
            ioc_path
        ),
    }
