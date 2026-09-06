from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CopilotAnswer:
    investigation_id: str
    question: str
    intent: str
    answer: str
    evidence_ids: list[str] = field(default_factory=list)
    related_investigations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)
