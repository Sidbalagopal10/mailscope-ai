from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    node_type: str
    value: str
    label: str

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    relationship: str
    evidence_source: str

    def to_dict(self):
        return asdict(self)
