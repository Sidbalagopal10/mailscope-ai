from __future__ import annotations

from typing import Any

from app.global_entity_registry.database import connection
from app.global_entity_registry.domain_utils import (
    normalize_hostname,
)


VERIFIED = "verified"
SUPPORTED = "supported"
UNKNOWN = "unknown"
CONFLICTING = "conflicting"


def decide_identity_state(
    *,
    domain_source_count: int,
    authoritative_domain_sources: int,
    high_confidence_legal_candidates: int,
    distinct_owners: int,
    strongest_domain_confidence: float,
) -> dict[str, Any]:
    if distinct_owners > 1:
        return {
            "identity_state": CONFLICTING,
            "confidence": 0.0,
            "reason": (
                "Multiple registry entities claim the "
                "same official domain."
            ),
        }

    if domain_source_count >= 2:
        return {
            "identity_state": VERIFIED,
            "confidence": max(
                0.95,
                min(
                    strongest_domain_confidence,
                    0.99,
                ),
            ),
            "reason": (
                "At least two independent domain identity "
                "sources agree."
            ),
        }

    if (
        authoritative_domain_sources >= 1
        and high_confidence_legal_candidates >= 1
    ):
        return {
            "identity_state": VERIFIED,
            "confidence": max(
                0.93,
                min(
                    strongest_domain_confidence,
                    0.98,
                ),
            ),
            "reason": (
                "Authoritative domain identity evidence "
                "is corroborated by high-confidence "
                "legal-entity evidence."
            ),
        }

    if domain_source_count >= 1:
        return {
            "identity_state": SUPPORTED,
            "confidence": max(
                0.60,
                min(
                    strongest_domain_confidence,
                    0.92,
                ),
            ),
            "reason": (
                "The domain is supported by at least "
                "one identity source."
            ),
        }

    return {
        "identity_state": UNKNOWN,
        "confidence": 0.0,
        "reason": (
            "No verified domain identity evidence "
            "was found."
        ),
    }


def evaluate_domain_identity(
    value: str,
) -> dict[str, Any]:
    hostname = normalize_hostname(
        value
    )

    if not hostname:
        return {
            "hostname": "",
            "identity_state": UNKNOWN,
            "confidence": 0.0,
            "security_effect": "neutral",
            "reason": (
                "The hostname could not be normalized."
            ),
        }

    with connection() as db:
        rows = db.execute(
            """
            SELECT
                d.id AS domain_id,
                d.entity_id,
                d.domain,
                d.confidence,
                d.verification_state,

                e.canonical_name,
                e.entity_type,
                e.country_code,
                e.country_name,
                e.continent

            FROM domains d

            JOIN entities e
              ON e.id = d.entity_id

            WHERE d.active = 1
            """
        ).fetchall()

        matches = []

        for row in rows:
            official = str(
                row[
                    "domain"
                ]
            ).lower()

            if (
                hostname == official
                or hostname.endswith(
                    "." + official
                )
            ):
                matches.append(
                    dict(row)
                )

        if not matches:
            return {
                "hostname": hostname,
                "identity_state": UNKNOWN,
                "confidence": 0.0,
                "security_effect": "neutral",
                "reason": (
                    "No official-domain identity "
                    "evidence was found."
                ),
                "official_domain": None,
                "entity": None,
                "sources": [],
                "legal_entity_candidates": [],
            }

        # Longest matching domain wins.
        matches.sort(
            key=lambda item: len(
                item[
                    "domain"
                ]
            ),
            reverse=True,
        )

        longest_length = len(
            matches[0][
                "domain"
            ]
        )

        relevant = [
            item
            for item in matches
            if len(
                item[
                    "domain"
                ]
            ) == longest_length
        ]

        official_domain = relevant[
            0
        ][
            "domain"
        ]

        same_domain = [
            item
            for item in relevant
            if item[
                "domain"
            ]
            == official_domain
        ]

        owners = {
            int(
                item[
                    "entity_id"
                ]
            )
            for item in same_domain
        }

        selected = same_domain[
            0
        ]

        domain_id = int(
            selected[
                "domain_id"
            ]
        )

        entity_id = int(
            selected[
                "entity_id"
            ]
        )

        evidence_rows = db.execute(
            """
            SELECT
                source_name,
                evidence_type,
                confidence,
                authoritative,
                source_record_id,
                observed_at

            FROM evidence_sources

            WHERE domain_id = ?
            """,
            (
                domain_id,
            ),
        ).fetchall()

        # Source names, not number of rows.
        source_names = {
            str(
                row[
                    "source_name"
                ]
            )
            for row in evidence_rows
        }

        authoritative_sources = {
            str(
                row[
                    "source_name"
                ]
            )
            for row in evidence_rows
            if bool(
                row[
                    "authoritative"
                ]
            )
        }

        confidence_values = [
            float(
                row[
                    "confidence"
                ]
            )
            for row in evidence_rows
        ]

        strongest_confidence = max(
            confidence_values,
            default=float(
                selected[
                    "confidence"
                ]
                or 0.0
            ),
        )

        legal_candidates = db.execute(
            """
            SELECT
                lei,
                name_similarity,
                country_agreement,
                confidence,
                decision,
                evidence

            FROM entity_resolution_candidates

            WHERE registry_entity_id = ?

            ORDER BY
                confidence DESC

            LIMIT 10
            """,
            (
                entity_id,
            ),
        ).fetchall()

        high_confidence_legal = sum(
            1
            for row in legal_candidates
            if (
                row[
                    "decision"
                ]
                == "high_confidence_candidate"
                and float(
                    row[
                        "confidence"
                    ]
                ) >= 0.95
            )
        )

        decision = decide_identity_state(
            domain_source_count=len(
                source_names
            ),
            authoritative_domain_sources=len(
                authoritative_sources
            ),
            high_confidence_legal_candidates=(
                high_confidence_legal
            ),
            distinct_owners=len(
                owners
            ),
            strongest_domain_confidence=(
                strongest_confidence
            ),
        )

        return {
            "hostname": hostname,
            "official_domain": (
                official_domain
            ),
            **decision,

            # Critical design rule:
            # identity evidence is NOT a safety verdict.
            "security_effect": (
                "identity_evidence_only"
            ),

            "entity": {
                "id": entity_id,
                "name": selected[
                    "canonical_name"
                ],
                "type": selected[
                    "entity_type"
                ],
                "country_code": selected[
                    "country_code"
                ],
                "country_name": selected[
                    "country_name"
                ],
                "continent": selected[
                    "continent"
                ],
            },

            "domain_relationship": (
                "exact"
                if hostname
                == official_domain
                else "true_subdomain"
            ),

            "sources": [
                dict(row)
                for row in evidence_rows
            ],

            "independent_domain_sources": (
                sorted(
                    source_names
                )
            ),

            "authoritative_domain_sources": (
                sorted(
                    authoritative_sources
                )
            ),

            "legal_entity_candidates": [
                dict(row)
                for row in legal_candidates
            ],

            "high_confidence_legal_candidates": (
                high_confidence_legal
            ),

            "distinct_domain_owners": (
                len(
                    owners
                )
            ),
        }
