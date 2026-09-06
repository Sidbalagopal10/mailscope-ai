from __future__ import annotations

from app.global_entity_registry.ingestion.website_policy import (
    evaluate_website_for_ingestion,
)
from app.global_entity_registry.models import (
    WebsiteRelationship,
)


def build_website_relationship(
    value: str,
    *,
    source_name: str | None = None,
    source_record_id: str | None = None,
    confidence: float = 0.50,
) -> WebsiteRelationship:
    decision = evaluate_website_for_ingestion(
        value
    )

    return WebsiteRelationship(
        original_value=(
            decision.original_value
        ),

        hostname=(
            decision.hostname
        ),

        relationship_type=(
            decision.relationship_type
        ),

        eligible_for_domain_identity=(
            decision.eligible_for_domain_identity
        ),

        preserve_as_relationship=(
            decision.preserve_as_relationship
        ),

        provider=(
            decision.provider
        ),

        platform_suffix=(
            decision.platform_suffix
        ),

        confidence=float(
            confidence
        ),

        source_name=(
            source_name
        ),

        source_record_id=(
            source_record_id
        ),

        reason=(
            decision.reason
        ),
    )
