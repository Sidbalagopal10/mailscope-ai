from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class HuntMatch:
    investigation_id: str
    target: str
    created_at: str
    verdict: str
    severity: float
    risk_level: str
    observable_type: str
    observable_value: str
    source: str
    confidence: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HuntResult:
    query: str
    observable_type: str | None
    matches: list[HuntMatch] = field(default_factory=list)
    scanned_reports: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "observable_type": self.observable_type,
            "match_count": len(self.matches),
            "scanned_reports": self.scanned_reports,
            "matches": [
                item.to_dict()
                for item in self.matches
            ],
            "metadata": self.metadata,
        }
