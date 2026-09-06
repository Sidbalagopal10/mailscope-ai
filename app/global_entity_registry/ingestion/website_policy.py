from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any
from urllib.parse import urlsplit

from app.website_relationships.classifier import (
    classify_website_relationship,
)


@dataclass(frozen=True)
class WebsiteIngestionDecision:
    original_value: str
    hostname: str

    relationship_type: str

    eligible_for_domain_identity: bool
    preserve_as_relationship: bool

    provider: str | None
    platform_suffix: str | None

    reason: str


def hostname_from_value(
    value: str | None,
) -> str:
    cleaned = str(
        value or ""
    ).strip()

    if not cleaned:
        return ""

    if "://" not in cleaned:
        cleaned = "https://" + cleaned

    try:
        return (
            urlsplit(
                cleaned
            ).hostname
            or ""
        ).lower().rstrip(".")

    except ValueError:
        return ""


def evaluate_website_for_ingestion(
    value: str | None,
) -> WebsiteIngestionDecision:
    original = str(
        value or ""
    ).strip()

    hostname = hostname_from_value(
        original
    )

    if not hostname:
        return WebsiteIngestionDecision(
            original_value=original,
            hostname="",
            relationship_type="invalid",
            eligible_for_domain_identity=False,
            preserve_as_relationship=False,
            provider=None,
            platform_suffix=None,
            reason=(
                "The supplied website value does not "
                "contain a usable hostname."
            ),
        )

    classification = (
        classify_website_relationship(
            original
        )
    )

    relationship_type = str(
        classification.get(
            "relationship_type",
            "unknown",
        )
    )

    eligible = bool(
        classification.get(
            "eligible_as_official_domain",
            False,
        )
    )

    # Platform/profile URLs can still be useful knowledge.
    # We preserve the relationship, but they must not become
    # official-domain ownership evidence.
    preserve = bool(
        relationship_type
        not in {
            "invalid",
            "unknown",
        }
    )

    return WebsiteIngestionDecision(
        original_value=original,
        hostname=hostname,
        relationship_type=relationship_type,
        eligible_for_domain_identity=eligible,
        preserve_as_relationship=preserve,
        provider=classification.get(
            "provider"
        ),
        platform_suffix=classification.get(
            "platform_suffix"
        ),
        reason=str(
            classification.get(
                "reason",
                "",
            )
        ),
    )


def decision_dict(
    value: str | None,
) -> dict[str, Any]:
    return asdict(
        evaluate_website_for_ingestion(
            value
        )
    )
