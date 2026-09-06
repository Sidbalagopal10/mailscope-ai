from __future__ import annotations

from dataclasses import (
    asdict,
    dataclass,
    field,
)
from typing import Any


VALID_VERDICTS = {
    "benign",
    "suspicious",
    "likely_phishing",
    "malicious",
    "insufficient_evidence",
}


@dataclass
class AnalystFinding:
    title: str

    explanation: str

    evidence_ids: list[str]

    severity: str = "info"


@dataclass
class AnalystReport:
    investigation_id: str

    verdict: str

    confidence: float

    executive_summary: str

    findings: list[AnalystFinding]

    recommended_actions: list[str]

    mitre_attack: list[dict[str, str]]

    limitations: list[str]

    model: str

    grounded: bool = False

    validation_errors: list[str] = field(
        default_factory=list
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def to_dict(
        self,
    ) -> dict[str, Any]:
        return asdict(
            self
        )
