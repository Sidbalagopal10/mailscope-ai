from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EvidenceFamily(str, Enum):
    IDENTITY = "identity"
    REPUTATION = "reputation"
    INFRASTRUCTURE = "infrastructure"
    BEHAVIOR = "behavior"
    CONTENT = "content"
    AUTHENTICATION = "authentication"


class EvidenceDirection(str, Enum):
    MALICIOUS = "malicious"
    BENIGN = "benign"
    NEUTRAL = "neutral"


class EvidenceStrength(str, Enum):
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    CRITICAL = "critical"


@dataclass
class Evidence:
    source: str
    family: EvidenceFamily
    direction: EvidenceDirection
    strength: EvidenceStrength

    confidence: float
    reason: str

    signal: str | None = None

    raw_value: Any = None

    exact_relevance: bool = True

    independent_group: str | None = None

    metadata: dict[str, Any] = field(
        default_factory=dict
    )


@dataclass
class FusionResult:
    risk_score: float
    confidence: float

    verdict: str
    risk_level: str

    malicious_evidence_count: int
    benign_evidence_count: int
    neutral_evidence_count: int

    corroborating_malicious_families: int

    contributions: list[dict[str, Any]]
    explanations: list[str]

    safeguards_triggered: list[str]

    identity_state: str | None = None
