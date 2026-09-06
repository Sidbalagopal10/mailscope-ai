from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from app.threat_enrichment.models import (
    EnrichmentSource,
)


def extract_hostname(
    value: str,
) -> str:
    candidate = (
        value.strip()
    )

    if not candidate:
        raise ValueError(
            "Target cannot be empty."
        )

    parsed = urlparse(
        candidate
        if "://" in candidate
        else f"https://{candidate}"
    )

    hostname = (
        parsed.hostname or ""
    ).strip().lower().rstrip(".")

    if not hostname:
        raise ValueError(
            "Unable to determine hostname."
        )

    return hostname


def _dict(
    value: Any,
) -> dict[str, Any]:
    if isinstance(
        value,
        dict,
    ):
        return value

    return {}


def _first_dict(
    payload: dict[str, Any],
    names: tuple[str, ...],
) -> dict[str, Any]:
    for name in names:
        value = payload.get(
            name
        )

        if isinstance(
            value,
            dict,
        ):
            return value

    return {}


def normalize_profile_source(
    *,
    source: str,
    payload: Any,
) -> EnrichmentSource:
    """
    Convert an existing unified-profile section into
    a stable source-level enrichment record.

    We deliberately retain the raw normalized section
    because provider schemas already contain useful
    deterministic detail and may evolve independently.
    """

    data = _dict(
        payload
    )

    if not data:
        return EnrichmentSource(
            source=source,
            status="unavailable",
            summary=(
                f"No {source} intelligence "
                f"was available."
            ),
        )

    error = data.get(
        "error"
    )

    if error:
        return EnrichmentSource(
            source=source,
            status="error",
            summary=(
                f"{source} intelligence "
                f"collection failed."
            ),
            evidence=data,
            error=str(
                error
            ),
        )

    observed_at = (
        data.get("observed_at")
        or data.get("checked_at")
        or data.get("updated_at")
        or data.get("lookup_at")
        or data.get("created_at")
    )

    return EnrichmentSource(
        source=source,
        status="available",
        summary=(
            f"{source} intelligence "
            f"was collected successfully."
        ),
        observed_at=(
            str(observed_at)
            if observed_at
            else None
        ),
        evidence=data,
    )


def normalize_unified_profile(
    profile: dict[str, Any],
) -> list[EnrichmentSource]:
    """
    Normalize intelligence already produced by the
    project's unified-domain intelligence pipeline.

    Multiple historical key names are intentionally
    supported because the project has evolved over time.
    """

    mappings = {
        "dns": (
            "dns",
            "dns_intelligence",
        ),

        "rdap": (
            "rdap",
            "rdap_intelligence",
        ),

        "certificate_transparency": (
            "certificate_transparency",
            "ct",
            "ct_intelligence",
        ),

        "ip_asn": (
            "ip_asn",
            "network",
            "network_intelligence",
            "ip_asn_intelligence",
        ),

        "threatfox": (
            "threatfox",
            "threatfox_intelligence",
        ),
    }

    sources: list[
        EnrichmentSource
    ] = []

    for source, names in mappings.items():
        section = _first_dict(
            profile,
            names,
        )

        sources.append(
            normalize_profile_source(
                source=source,
                payload=section,
            )
        )

    return sources
