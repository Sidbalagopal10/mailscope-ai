from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


VALID_STATUSES = {
    "available",
    "unavailable",
    "error",
    "not_applicable",
}


@dataclass
class EnrichmentSource:
    """
    Normalized result from one intelligence source.

    `status` describes collection state only.
    It is NOT a malicious/benign verdict.
    """

    source: str
    status: str
    summary: str
    observed_at: str | None = None
    confidence: float | None = None
    indicators: list[str] = field(
        default_factory=list
    )
    evidence: dict[str, Any] = field(
        default_factory=dict
    )
    error: str | None = None

    def __post_init__(self) -> None:
        if self.status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid enrichment status: "
                f"{self.status}"
            )

        if self.confidence is not None:
            self.confidence = max(
                0.0,
                min(
                    1.0,
                    float(self.confidence),
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "status": self.status,
            "summary": self.summary,
            "observed_at": self.observed_at,
            "confidence": self.confidence,
            "indicators": list(
                self.indicators
            ),
            "evidence": dict(
                self.evidence
            ),
            "error": self.error,
        }


@dataclass
class ThreatEnrichment:
    """
    Canonical threat-intelligence enrichment object.

    This object contains observations only.
    It does not replace the Core Engine risk decision.
    """

    target: str
    hostname: str
    created_at: str

    sources: list[EnrichmentSource] = field(
        default_factory=list
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    @property
    def available_sources(self) -> int:
        return sum(
            1
            for source in self.sources
            if source.status == "available"
        )

    @property
    def failed_sources(self) -> int:
        return sum(
            1
            for source in self.sources
            if source.status == "error"
        )

    def source(
        self,
        name: str,
    ) -> EnrichmentSource | None:
        for item in self.sources:
            if item.source == name:
                return item

        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "hostname": self.hostname,
            "created_at": self.created_at,

            "sources": [
                source.to_dict()
                for source in self.sources
            ],

            "summary": {
                "source_count": len(
                    self.sources
                ),

                "available_sources": (
                    self.available_sources
                ),

                "failed_sources": (
                    self.failed_sources
                ),
            },

            "metadata": dict(
                self.metadata
            ),
        }
