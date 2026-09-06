from __future__ import annotations

import json
from pathlib import Path

from app.analyst.evidence import (
    InvestigationEvidence,
)


DEFAULT_DIRECTORY = Path(
    "data/investigations"
)


def save_evidence(
    evidence: InvestigationEvidence,
    *,
    directory: Path = DEFAULT_DIRECTORY,
) -> Path:
    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = (
        directory
        / (
            evidence.investigation_id
            + ".json"
        )
    )

    path.write_text(
        json.dumps(
            evidence.to_dict(),
            indent=2,
            sort_keys=True,
            default=str,
        ),
        encoding="utf-8",
    )

    return path
