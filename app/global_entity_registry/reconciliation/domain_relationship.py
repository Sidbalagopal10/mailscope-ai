from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.global_entity_registry.domain_utils import (
    canonical_identity_domain,
)
from app.global_entity_registry.public_suffix import (
    registrable_domain,
)


@dataclass(frozen=True)
class DomainRelationship:
    first_domain: str
    second_domain: str

    first_registrable: str
    second_registrable: str

    relationship: str
    confidence: float

    reason: str


def classify_domain_relationship(
    first: str,
    second: str,
) -> DomainRelationship:
    left = canonical_identity_domain(
        first
    )

    right = canonical_identity_domain(
        second
    )

    if not left or not right:
        return DomainRelationship(
            first_domain=left,
            second_domain=right,
            first_registrable="",
            second_registrable="",
            relationship="unresolved",
            confidence=0.0,
            reason="One or both domains are invalid.",
        )

    left_reg = (
        registrable_domain(
            left
        )
        or left
    )

    right_reg = (
        registrable_domain(
            right
        )
        or right
    )

    if left == right:
        return DomainRelationship(
            first_domain=left,
            second_domain=right,
            first_registrable=left_reg,
            second_registrable=right_reg,
            relationship="exact_agreement",
            confidence=1.0,
            reason=(
                "Both sources resolve to the same "
                "canonical hostname."
            ),
        )

    if left_reg == right_reg:
        return DomainRelationship(
            first_domain=left,
            second_domain=right,
            first_registrable=left_reg,
            second_registrable=right_reg,
            relationship="same_registrable_domain",
            confidence=0.95,
            reason=(
                "Both hostnames belong to the same "
                "registrable domain."
            ),
        )

    if (
        left.endswith(
            "." + right
        )
        or right.endswith(
            "." + left
        )
    ):
        return DomainRelationship(
            first_domain=left,
            second_domain=right,
            first_registrable=left_reg,
            second_registrable=right_reg,
            relationship="related_subdomain",
            confidence=0.95,
            reason=(
                "One hostname is a true subdomain "
                "of the other."
            ),
        )

    return DomainRelationship(
        first_domain=left,
        second_domain=right,
        first_registrable=left_reg,
        second_registrable=right_reg,
        relationship="different_registrable_domains",
        confidence=0.0,
        reason=(
            "The two sources point to different "
            "registrable domains."
        ),
    )
