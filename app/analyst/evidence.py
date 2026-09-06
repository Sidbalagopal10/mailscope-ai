from __future__ import annotations

from dataclasses import (
    asdict,
    dataclass,
    field,
)
from datetime import (
    datetime,
    timezone,
)
from typing import Any


@dataclass
class EvidenceFinding:
    """
    One observable security fact.

    Example:
        category = "identity"
        title = "Organization identity unknown"
        severity = "info"

    Findings are facts supplied to the AI analyst.
    """

    category: str
    title: str

    description: str

    severity: str = "info"

    source: str = ""

    confidence: float | None = None

    raw: dict[
        str,
        Any,
    ] = field(
        default_factory=dict
    )


@dataclass
class InvestigationEvidence:
    """
    Normalized evidence package consumed by the
    AI Security Analyst.

    This object does NOT make the final AI verdict.
    """

    investigation_id: str

    target: str

    target_type: str

    created_at: str

    core: dict[
        str,
        Any,
    ]

    identity: dict[
        str,
        Any,
    ]

    findings: list[
        EvidenceFinding
    ]

    intelligence: dict[
        str,
        Any,
    ] = field(
        default_factory=dict
    )

    metadata: dict[
        str,
        Any,
    ] = field(
        default_factory=dict
    )

    def to_dict(
        self,
    ) -> dict[str, Any]:
        return asdict(
            self
        )


def utc_now() -> str:
    return (
        datetime.now(
            timezone.utc
        )
        .isoformat()
    )
