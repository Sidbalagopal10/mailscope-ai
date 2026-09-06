from __future__ import annotations

from dataclasses import (
    asdict,
    dataclass,
    field,
)
from typing import Any


@dataclass
class TimelineEvent:
    timestamp: str
    event_type: str
    title: str
    description: str
    source: str


@dataclass
class IOC:
    type: str
    value: str
    source: str
    confidence: float | None = None


@dataclass
class ReportFinding:
    title: str
    explanation: str
    severity: str
    evidence_ids: list[str]


@dataclass
class InvestigationReport:
    investigation_id: str

    created_at: str

    target: str
    target_type: str

    verdict: str
    confidence: float
    severity: float
    risk_level: str

    executive_summary: str

    findings: list[ReportFinding]

    identity: dict[str, Any]

    mitre_attack: list[dict[str, str]]

    iocs: list[IOC]

    timeline: list[TimelineEvent]

    recommendations: list[str]

    limitations: list[str]

    evidence: dict[str, Any]

    analyst_model: str

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def to_dict(
        self,
    ) -> dict[str, Any]:
        return asdict(
            self
        )
