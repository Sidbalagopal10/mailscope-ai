from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


ExpectedLabel = Literal[
    "benign",
    "malicious",
]


@dataclass
class BenchmarkCase:
    value: str
    expected_label: ExpectedLabel
    source: str

    source_rank: int | None = None
    metadata: dict | None = None
