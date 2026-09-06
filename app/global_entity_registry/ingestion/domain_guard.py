from __future__ import annotations

from typing import Any

from app.global_entity_registry.ingestion.website_policy import (
    evaluate_website_for_ingestion,
)


def classify_source_website(
    *,
    source_name: str,
    entity_name: str,
    website: str,
) -> dict[str, Any]:
    decision = evaluate_website_for_ingestion(
        website
    )

    return {
        "source_name": source_name,
        "entity_name": entity_name,
        "website": website,

        "hostname": decision.hostname,

        "relationship_type": (
            decision.relationship_type
        ),

        "eligible_for_domain_identity": (
            decision.eligible_for_domain_identity
        ),

        "preserve_as_relationship": (
            decision.preserve_as_relationship
        ),

        "provider": (
            decision.provider
        ),

        "platform_suffix": (
            decision.platform_suffix
        ),

        "reason": (
            decision.reason
        ),
    }


def should_create_domain_identity(
    website: str,
) -> bool:
    return bool(
        evaluate_website_for_ingestion(
            website
        ).eligible_for_domain_identity
    )
