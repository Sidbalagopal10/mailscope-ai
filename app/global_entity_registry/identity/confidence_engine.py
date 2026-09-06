from __future__ import annotations

import math
from collections import defaultdict
from typing import Any

from app.global_entity_registry.database import (
    connection,
)
from app.global_entity_registry.domain_utils import (
    canonical_identity_domain,
)
from app.global_entity_registry.identity.confidence_model import (
    IdentityConfidenceResult,
)
from app.global_entity_registry.identity.evaluator import (
    assess_domain_identity,
)
from app.global_entity_registry.identity.web_presence import (
    WebPresenceMode,
    assess_web_presence,
)
from app.global_entity_registry.identity.evidence_state import (
    IdentityEvidenceState,
)


STATE_CAPS = {
    IdentityEvidenceState.VERIFIED: 99.0,
    IdentityEvidenceState.SUPPORTED: 89.0,
    IdentityEvidenceState.CONFLICTING: 69.0,
    IdentityEvidenceState.UNKNOWN: 20.0,
}


def confidence_band(
    score: float,
) -> str:
    if score >= 95:
        return "very_high"

    if score >= 80:
        return "high"

    if score >= 60:
        return "moderate"

    if score >= 30:
        return "low"

    return "very_low"


def _evidence_rows(
    *,
    entity_id: int,
    domain: str,
) -> list[dict[str, Any]]:
    canonical = canonical_identity_domain(
        domain
    )

    with connection() as db:
        rows = db.execute(
            """
            SELECT
                es.source_name,
                es.evidence_type,
                es.confidence,
                es.authoritative,
                es.source_record_id,
                es.raw_reference

            FROM domains d

            JOIN evidence_sources es
              ON es.domain_id = d.id

            WHERE d.entity_id = ?
              AND d.domain = ?

            ORDER BY
                es.source_name,
                es.confidence DESC
            """,
            (
                int(
                    entity_id
                ),
                canonical,
            ),
        ).fetchall()

    return [
        dict(
            row
        )
        for row in rows
    ]


def _best_source_confidences(
    rows: list[dict[str, Any]],
) -> dict[str, float]:
    """
    One source receives one vote.

    Multiple rows from the same source must not
    artificially inflate identity confidence.
    """

    result: dict[
        str,
        float,
    ] = {}

    for row in rows:
        source = str(
            row.get(
                "source_name"
            )
            or ""
        ).strip()

        if not source:
            continue

        try:
            confidence = float(
                row.get(
                    "confidence"
                )
                or 0.0
            )

        except (
            TypeError,
            ValueError,
        ):
            confidence = 0.0

        confidence = min(
            max(
                confidence,
                0.0,
            ),
            1.0,
        )

        result[
            source
        ] = max(
            result.get(
                source,
                0.0,
            ),
            confidence,
        )

    return result


def _independent_support_probability(
    source_confidences: dict[
        str,
        float,
    ],
) -> float:
    """
    Combine independent supporting sources:

        1 - Π(1 - confidence_i)

    Example:

        0.97 + 0.82
            -> 0.9946 combined support

    The state cap later prevents this mathematical
    combination from overriding conflicts or ambiguity.
    """

    if not source_confidences:
        return 0.0

    failure_probability = 1.0

    for confidence in (
        source_confidences.values()
    ):
        failure_probability *= (
            1.0
            - confidence
        )

    return min(
        max(
            1.0
            - failure_probability,
            0.0,
        ),
        1.0,
    )


def _authoritative_sources(
    rows: list[dict[str, Any]],
) -> tuple[str, ...]:
    values = {
        str(
            row.get(
                "source_name"
            )
        )
        for row in rows
        if (
            row.get(
                "source_name"
            )
            and int(
                row.get(
                    "authoritative"
                )
                or 0
            )
            == 1
        )
    }

    return tuple(
        sorted(
            values
        )
    )


def _competing_entities(
    domain: str,
    *,
    expected_entity_id: int,
) -> tuple[str, ...]:
    canonical = canonical_identity_domain(
        domain
    )

    with connection() as db:
        rows = db.execute(
            """
            SELECT DISTINCT
                e.id,
                e.canonical_name

            FROM domains d

            JOIN entities e
              ON e.id = d.entity_id

            WHERE d.domain = ?
              AND e.id != ?

            ORDER BY e.canonical_name
            """,
            (
                canonical,
                int(
                    expected_entity_id
                ),
            ),
        ).fetchall()

    return tuple(
        str(
            row[
                "canonical_name"
            ]
        )
        for row in rows
    )


def _state_floor(
    state: IdentityEvidenceState,
) -> float:
    """
    Floors prevent a high-quality verified identity from
    receiving an accidentally tiny score because of a
    sparse metadata field.

    They do NOT establish maliciousness or safety.
    """

    return {
        IdentityEvidenceState.VERIFIED: 90.0,
        IdentityEvidenceState.SUPPORTED: 55.0,
        IdentityEvidenceState.CONFLICTING: 30.0,
        IdentityEvidenceState.UNKNOWN: 0.0,
    }[
        state
    ]


def score_identity(
    domain: str,
) -> list[
    IdentityConfidenceResult
]:
    assessments = assess_domain_identity(
        domain
    )

    results = []

    for assessment in assessments:
        if (
            assessment.entity_id
            is None
            or assessment.state
            == IdentityEvidenceState.UNKNOWN
        ):
            results.append(
                IdentityConfidenceResult(
                    entity_id=None,
                    canonical_name=None,
                    domain=assessment.domain,
                    evidence_state=(
                        assessment.state.value
                    ),
                    confidence_score=0.0,
                    confidence_band="very_low",
                    source_count=0,
                    sources=(),
                    authoritative_sources=(),
                    conflicting_domains=(),
                    competing_entities=(),
                    reasons=(
                        "No organization identity evidence "
                        "currently establishes ownership.",
                    ),
                    factors={
                        "independent_support_probability": 0.0,
                        "state_cap": 20.0,
                        "state_floor": 0.0,
                        "conflict_penalty": 0.0,
                        "ownership_ambiguity_penalty": 0.0,
                    },
                )
            )

            continue

        rows = _evidence_rows(
            entity_id=(
                assessment.entity_id
            ),
            domain=assessment.domain,
        )

        source_confidences = (
            _best_source_confidences(
                rows
            )
        )

        independent_support = (
            _independent_support_probability(
                source_confidences
            )
        )

        authoritative = (
            _authoritative_sources(
                rows
            )
        )

        competitors = (
            _competing_entities(
                assessment.domain,
                expected_entity_id=(
                    assessment.entity_id
                ),
            )
        )

        web_presence = (
            assess_web_presence(
                assessment.domain
            )
        )

        raw_score = (
            independent_support
            * 100.0
        )

        state_cap = STATE_CAPS[
            assessment.state
        ]

        state_floor = _state_floor(
            assessment.state
        )

        reasons = []

        if len(
            source_confidences
        ) >= 2:
            reasons.append(
                f"{len(source_confidences)} independent "
                "sources support the same canonical domain."
            )

        elif len(
            source_confidences
        ) == 1:
            reasons.append(
                "One independent source currently supports "
                "this organization-domain relationship."
            )

        if authoritative:
            reasons.append(
                "Authoritative evidence present from: "
                + ", ".join(
                    authoritative
                )
                + "."
            )

        conflict_penalty = 0.0

        if assessment.conflicting_domains:
            # Conflict reduces certainty, but does NOT imply
            # phishing or maliciousness.
            conflict_penalty = min(
                20.0,
                6.0
                * len(
                    assessment.conflicting_domains
                ),
            )

            reasons.append(
                "Independent evidence points to alternate "
                "candidate domain(s): "
                + ", ".join(
                    assessment.conflicting_domains
                )
                + "."
            )

        ambiguity_penalty = 0.0

        if competitors:
            if (
                web_presence.mode
                == WebPresenceMode.SHARED
            ):
                reasons.append(
                    "The hostname is shared by multiple "
                    "legitimate organizational web "
                    "presences; this does not reduce "
                    "identity confidence by itself."
                )

            elif (
                web_presence.mode
                == WebPresenceMode.AMBIGUOUS
            ):
                reasons.append(
                    "Multiple organization records use "
                    "this hostname. The relationship is "
                    "currently classified as ambiguous "
                    "rather than conflicting ownership."
                )

            else:
                reasons.append(
                    "Additional organization records are "
                    "associated with this hostname: "
                    + ", ".join(
                        competitors
                    )
                    + "."
                )

        score = max(
            raw_score,
            state_floor,
        )

        score -= (
            conflict_penalty
        )

        score -= (
            ambiguity_penalty
        )

        score = min(
            score,
            state_cap,
        )

        score = max(
            score,
            0.0,
        )

        score = round(
            score,
            1,
        )

        if (
            not assessment.conflicting_domains
            and not competitors
        ):
            reasons.append(
                "No conflicting domain or competing "
                "organization ownership was observed."
            )

        # Carry the evidence-state explanation forward.
        for reason in (
            assessment.reasons
        ):
            if reason not in reasons:
                reasons.append(
                    reason
                )

        results.append(
            IdentityConfidenceResult(
                entity_id=(
                    assessment.entity_id
                ),

                canonical_name=(
                    assessment.canonical_name
                ),

                domain=(
                    assessment.domain
                ),

                evidence_state=(
                    assessment.state.value
                ),

                confidence_score=(
                    score
                ),

                confidence_band=(
                    confidence_band(
                        score
                    )
                ),

                source_count=len(
                    source_confidences
                ),

                sources=tuple(
                    sorted(
                        source_confidences
                    )
                ),

                authoritative_sources=(
                    authoritative
                ),

                conflicting_domains=(
                    assessment.conflicting_domains
                ),

                competing_entities=(
                    competitors
                ),

                reasons=tuple(
                    reasons
                ),

                factors={
                    "source_confidences": (
                        source_confidences
                    ),

                    "independent_support_probability": round(
                        independent_support,
                        6,
                    ),

                    "raw_support_score": round(
                        raw_score,
                        2,
                    ),

                    "state_cap": (
                        state_cap
                    ),

                    "state_floor": (
                        state_floor
                    ),

                    "conflict_penalty": (
                        conflict_penalty
                    ),

                    "ownership_ambiguity_penalty": (
                        ambiguity_penalty
                    ),

                    "web_presence_mode": (
                        web_presence.mode.value
                    ),

                    "web_presence_entity_count": (
                        web_presence.entity_count
                    ),
                },
            )
        )

    results.sort(
        key=lambda item: (
            item.confidence_score,
            item.source_count,
        ),
        reverse=True,
    )

    return results
