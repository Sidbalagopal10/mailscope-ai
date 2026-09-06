from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class IdentityConfidenceResult:
    entity_id: int | None
    canonical_name: str | None

    domain: str

    evidence_state: str

    confidence_score: float
    confidence_band: str

    source_count: int
    sources: tuple[str, ...]

    authoritative_sources: tuple[str, ...]

    conflicting_domains: tuple[str, ...]

    competing_entities: tuple[str, ...]

    reasons: tuple[str, ...]

    factors: dict[str, Any]
