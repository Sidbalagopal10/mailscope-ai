from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class IdentityEvidenceState(
    str,
    Enum,
):
    VERIFIED = "verified"
    SUPPORTED = "supported"
    CONFLICTING = "conflicting"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class IdentityEvidenceAssessment:
    entity_id: int | None
    canonical_name: str | None

    domain: str

    state: IdentityEvidenceState

    source_count: int
    sources: tuple[str, ...]

    confidence: float

    reasons: tuple[str, ...]

    conflicting_domains: tuple[
        str,
        ...
    ] = ()

    metadata: dict[
        str,
        Any,
    ] | None = None
