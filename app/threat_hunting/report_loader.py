import json
from pathlib import Path
from typing import Any


DEFAULT_REPORT_ROOT = Path(
    "data/investigations/reports"
)


def _looks_like_report(
    payload: dict[str, Any],
) -> bool:
    return bool(
        payload.get("investigation_id")
        and payload.get("target")
    )


def load_investigation_reports(
    root: Path | str = DEFAULT_REPORT_ROOT,
) -> list[dict[str, Any]]:
    """
    Load canonical investigation report JSON files.

    Invalid, unrelated, or partially written JSON files are
    ignored rather than breaking threat hunting.
    """

    root = Path(root)

    if not root.exists():
        return []

    reports: dict[
        str,
        dict[str, Any],
    ] = {}

    for path in root.rglob("*.json"):
        try:
            payload = json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            continue

        if not isinstance(
            payload,
            dict,
        ):
            continue

        # Some export containers may wrap the report.
        if (
            "report" in payload
            and isinstance(
                payload["report"],
                dict,
            )
        ):
            payload = payload[
                "report"
            ]

        if not _looks_like_report(
            payload
        ):
            continue

        investigation_id = str(
            payload[
                "investigation_id"
            ]
        )

        reports[
            investigation_id
        ] = payload

    return sorted(
        reports.values(),
        key=lambda item: (
            str(
                item.get(
                    "created_at",
                    "",
                )
            ),
            str(
                item.get(
                    "investigation_id",
                    "",
                )
            ),
        ),
        reverse=True,
    )
