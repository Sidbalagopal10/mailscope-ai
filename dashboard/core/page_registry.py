from __future__ import annotations

from pathlib import Path
from typing import Iterable


DASHBOARD_DIRECTORY = Path(__file__).resolve().parents[1]
PAGES_DIRECTORY = DASHBOARD_DIRECTORY / "pages"


def find_page(
    patterns: Iterable[str],
) -> Path | None:
    """
    Locate the first existing page matching one of the supplied
    glob patterns.

    This keeps the consolidated router compatible with the page
    filenames already present in the project.
    """
    for pattern in patterns:
        matches = sorted(
            PAGES_DIRECTORY.glob(
                pattern
            )
        )

        for match in matches:
            if match.is_file():
                return match

    return None


def relative_page_path(
    path: Path,
) -> str:
    """
    Return a page path relative to the project-root Streamlit
    entry point: streamlit_app.py.

    Example:
        dashboard/pages/16_Unified_Email_Security_Pipeline.py
    """
    project_root = (
        DASHBOARD_DIRECTORY.parent
    )

    return str(
        path.resolve().relative_to(
            project_root.resolve()
        )
    )
