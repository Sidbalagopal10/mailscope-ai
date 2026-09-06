from __future__ import annotations

from dataclasses import asdict
from typing import Any
from urllib.parse import urlsplit

from app.hosting_intelligence.providers import (
    PROVIDERS,
)


def hostname_from_value(
    value: str,
) -> str:
    cleaned = str(
        value or ""
    ).strip()

    if not cleaned:
        return ""

    if "://" not in cleaned:
        cleaned = (
            "https://"
            + cleaned
        )

    try:
        return (
            urlsplit(
                cleaned
            ).hostname
            or ""
        ).lower().rstrip(".")

    except ValueError:
        return ""


def hostname_matches_suffix(
    hostname: str,
    suffix: str,
) -> bool:
    host = str(
        hostname
    ).lower().rstrip(".")

    suffix = str(
        suffix
    ).lower().rstrip(".")

    return bool(
        host == suffix
        or host.endswith(
            "." + suffix
        )
    )


def identify_hosting(
    value: str,
) -> dict[str, Any]:
    hostname = hostname_from_value(
        value
    )

    if not hostname:
        return {
            "matched": False,
            "hostname": "",
            "hosting_state": "unknown",
            "risk_effect": "neutral",
        }

    candidates = [
        provider
        for provider in PROVIDERS
        if hostname_matches_suffix(
            hostname,
            provider.suffix,
        )
    ]

    if not candidates:
        return {
            "matched": False,
            "hostname": hostname,
            "hosting_state": "unknown",
            "risk_effect": "neutral",
            "provider": None,
            "platform": None,
            "category": None,
            "hosting_type": None,
            "user_generated": None,
            "shared_infrastructure": None,
            "requires_corroboration": False,
        }

    # Longest suffix wins if fingerprints overlap.
    candidates.sort(
        key=lambda item: len(
            item.suffix
        ),
        reverse=True,
    )

    best = candidates[0]

    return {
        "matched": True,
        "hostname": hostname,
        "hosting_state": (
            "known_shared_platform"
            if best.shared_infrastructure
            else "known_platform"
        ),
        **asdict(
            best
        ),
    }
