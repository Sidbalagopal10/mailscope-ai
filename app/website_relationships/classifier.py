from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from app.website_relationships.platforms import (
    PLATFORMS,
)


def hostname_from_url(
    value: str,
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


def matches_suffix(
    hostname: str,
    suffix: str,
) -> bool:
    host = hostname.lower().rstrip(".")
    target = suffix.lower().rstrip(".")

    return bool(
        host == target
        or host.endswith(
            "." + target
        )
    )


def classify_website_relationship(
    value: str,
) -> dict[str, Any]:
    hostname = hostname_from_url(
        value
    )

    if not hostname:
        return {
            "hostname": "",
            "relationship_type": "unknown",
            "platform_match": False,
            "eligible_as_official_domain": False,
            "reason": "No valid hostname.",
        }

    candidates = [
        item
        for item in PLATFORMS
        if matches_suffix(
            hostname,
            item.suffix,
        )
    ]

    if candidates:
        candidates.sort(
            key=lambda item: len(
                item.suffix
            ),
            reverse=True,
        )

        platform = candidates[0]

        return {
            "hostname": hostname,
            "relationship_type": (
                platform.relationship_type
            ),
            "platform_match": True,
            "provider": platform.provider,
            "platform_suffix": platform.suffix,
            "user_generated": (
                platform.user_generated
            ),
            "shared_platform": (
                platform.shared_platform
            ),
            "eligible_as_official_domain": (
                platform.can_be_official_root_domain
            ),
            "reason": platform.notes,
        }

    return {
        "hostname": hostname,
        "relationship_type": (
            "official_website_candidate"
        ),
        "platform_match": False,
        "provider": None,
        "platform_suffix": None,
        "user_generated": False,
        "shared_platform": False,

        # IMPORTANT:
        # candidate, not verified.
        "eligible_as_official_domain": True,

        "reason": (
            "The hostname is not a recognized shared/profile "
            "platform. Additional source agreement is still "
            "required before official ownership is established."
        ),
    }
