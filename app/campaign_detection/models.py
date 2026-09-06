from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class CorrelationArtifact:
    type: str
    value: str
    source: str
    confidence: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CampaignRelationship:
    investigation_a: str
    investigation_b: str

    artifact_type: str
    artifact_value: str

    strength: float
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CampaignCandidate:
    campaign_id: str

    investigation_ids: list[str]

    relationships: list[CampaignRelationship]

    shared_artifacts: list[CorrelationArtifact]

    correlation_score: float
    strength: str

    first_seen: str | None = None
    last_seen: str | None = None

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
