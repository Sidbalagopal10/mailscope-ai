from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from app.global_entity_registry.domain_utils import (
    canonical_identity_domain,
)
from app.global_entity_registry.identity.confidence_engine import (
    score_identity,
)
from app.global_entity_registry.identity.web_presence import (
    assess_web_presence,
)


def hostname_from_input(
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


def explain_identity(
    value: str,
) -> dict[str, Any]:
    hostname = hostname_from_input(
        value
    )

    canonical = canonical_identity_domain(
        hostname
    )

    if not canonical:
        return {
            "input": value,
            "hostname": "",
            "canonical_domain": "",
            "identity_known": False,
            "best_match": None,
            "matches": [],
            "web_presence": None,
        }

    matches = score_identity(
        canonical
    )

    web_presence = (
        assess_web_presence(
            canonical
        )
    )

    serialized = []

    for match in matches:
        serialized.append(
            {
                "entity_id": (
                    match.entity_id
                ),

                "organization": (
                    match.canonical_name
                ),

                "domain": (
                    match.domain
                ),

                "evidence_state": (
                    match.evidence_state
                ),

                "confidence_score": (
                    match.confidence_score
                ),

                "confidence_band": (
                    match.confidence_band
                ),

                "source_count": (
                    match.source_count
                ),

                "sources": list(
                    match.sources
                ),

                "authoritative_sources": list(
                    match.authoritative_sources
                ),

                "conflicting_domains": list(
                    match.conflicting_domains
                ),

                "competing_entities": list(
                    match.competing_entities
                ),

                "reasons": list(
                    match.reasons
                ),

                "factors": (
                    match.factors
                ),
            }
        )

    best = (
        serialized[0]
        if serialized
        else None
    )

    return {
        "input": value,

        "hostname": (
            hostname
        ),

        "canonical_domain": (
            canonical
        ),

        "identity_known": bool(
            best
            and best.get(
                "evidence_state"
            )
            != "unknown"
        ),

        "best_match": (
            best
        ),

        "matches": (
            serialized
        ),

        "web_presence": {
            "mode": (
                web_presence.mode.value
            ),

            "entity_count": (
                web_presence.entity_count
            ),

            "entities": list(
                web_presence.entities
            ),

            "reason": (
                web_presence.reason
            ),
        },
    }
