from __future__ import annotations

import hashlib
from collections import defaultdict
from itertools import combinations

from app.campaign_detection.artifacts import artifacts_from_report
from app.campaign_detection.models import (
    CampaignCandidate,
    CampaignRelationship,
    CorrelationArtifact,
)
from app.campaign_detection.policy import (
    artifact_weight,
    relationship_rationale,
    score_strength,
)
from app.reports.models import InvestigationReport


MINIMUM_CAMPAIGN_SCORE = 0.60


def _campaign_id(
    investigation_ids: list[str],
) -> str:
    material = "|".join(
        sorted(investigation_ids)
    )

    digest = hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()[:16]

    return f"campaign-{digest}"


def _pair_key(
    left: str,
    right: str,
) -> tuple[str, str]:
    return tuple(sorted((left, right)))


def _combined_pair_score(
    relationships: list[CampaignRelationship],
) -> float:
    """
    Combine independent signals without allowing the total
    to exceed 1.0.

    Example:
    domain 0.60 + IP 0.45
    => 1 - ((1-.60) * (1-.45))
    => 0.78
    """

    remaining = 1.0

    for relationship in relationships:
        weight = max(
            0.0,
            min(
                1.0,
                relationship.strength,
            ),
        )

        remaining *= (
            1.0 - weight
        )

    return round(
        1.0 - remaining,
        4,
    )


def _connected_components(
    edges: set[tuple[str, str]],
) -> list[set[str]]:
    adjacency: dict[
        str,
        set[str],
    ] = defaultdict(set)

    for left, right in edges:
        adjacency[left].add(right)
        adjacency[right].add(left)

    visited: set[str] = set()
    components: list[set[str]] = []

    for node in sorted(adjacency):
        if node in visited:
            continue

        stack = [node]
        component: set[str] = set()

        while stack:
            current = stack.pop()

            if current in visited:
                continue

            visited.add(current)
            component.add(current)

            stack.extend(
                adjacency[current]
                - visited
            )

        if len(component) >= 2:
            components.append(
                component
            )

    return components


def correlate_reports(
    reports: list[InvestigationReport],
) -> list[CampaignCandidate]:
    """
    Deterministically correlate canonical investigation reports.

    Security boundaries:
    - no AI
    - no network calls
    - no new threat facts
    - no threat-actor attribution
    - report IOCs only
    """

    if len(reports) < 2:
        return []

    reports_by_id = {
        report.investigation_id: report
        for report in reports
    }

    artifact_index: dict[
        tuple[str, str],
        set[str],
    ] = defaultdict(set)

    artifact_objects: dict[
        tuple[str, str],
        CorrelationArtifact,
    ] = {}

    for report in reports:
        for artifact in artifacts_from_report(
            report
        ):
            key = (
                artifact.type,
                artifact.value,
            )

            artifact_index[key].add(
                report.investigation_id
            )

            artifact_objects[key] = artifact

    relationships: list[
        CampaignRelationship
    ] = []

    for (
        artifact_type,
        artifact_value,
    ), investigation_ids in artifact_index.items():

        if len(investigation_ids) < 2:
            continue

        weight = artifact_weight(
            artifact_type
        )

        if weight <= 0:
            continue

        for left, right in combinations(
            sorted(investigation_ids),
            2,
        ):
            relationships.append(
                CampaignRelationship(
                    investigation_a=left,
                    investigation_b=right,
                    artifact_type=artifact_type,
                    artifact_value=artifact_value,
                    strength=weight,
                    rationale=(
                        relationship_rationale(
                            artifact_type
                        )
                    ),
                )
            )

    pair_relationships: dict[
        tuple[str, str],
        list[CampaignRelationship],
    ] = defaultdict(list)

    for relationship in relationships:
        pair_relationships[
            _pair_key(
                relationship.investigation_a,
                relationship.investigation_b,
            )
        ].append(
            relationship
        )

    qualifying_edges: set[
        tuple[str, str]
    ] = set()

    for pair, items in pair_relationships.items():
        score = _combined_pair_score(items)

        if score >= MINIMUM_CAMPAIGN_SCORE:
            qualifying_edges.add(pair)

    components = _connected_components(
        qualifying_edges
    )

    campaigns: list[
        CampaignCandidate
    ] = []

    for component in components:
        investigation_ids = sorted(
            component
        )

        component_relationships = [
            relationship
            for relationship in relationships
            if (
                relationship.investigation_a in component
                and
                relationship.investigation_b in component
            )
        ]

        pair_scores: list[float] = []

        for pair, items in pair_relationships.items():
            if (
                pair in qualifying_edges
                and pair[0] in component
                and pair[1] in component
            ):
                pair_scores.append(
                    _combined_pair_score(items)
                )

        correlation_score = (
            round(
                sum(pair_scores)
                / len(pair_scores),
                4,
            )
            if pair_scores
            else 0.0
        )

        shared_keys = {
            (
                relationship.artifact_type,
                relationship.artifact_value,
            )
            for relationship
            in component_relationships
        }

        shared_artifacts = [
            artifact_objects[key]
            for key in sorted(shared_keys)
        ]

        timestamps = [
            reports_by_id[
                investigation_id
            ].created_at
            for investigation_id
            in investigation_ids
            if reports_by_id[
                investigation_id
            ].created_at
        ]

        campaigns.append(
            CampaignCandidate(
                campaign_id=(
                    _campaign_id(
                        investigation_ids
                    )
                ),
                investigation_ids=(
                    investigation_ids
                ),
                relationships=(
                    component_relationships
                ),
                shared_artifacts=(
                    shared_artifacts
                ),
                correlation_score=(
                    correlation_score
                ),
                strength=(
                    score_strength(
                        correlation_score
                    )
                ),
                first_seen=(
                    min(timestamps)
                    if timestamps
                    else None
                ),
                last_seen=(
                    max(timestamps)
                    if timestamps
                    else None
                ),
                metadata={
                    "engine_version": (
                        "campaign-correlation-v1.0"
                    ),
                    "deterministic": True,
                    "ai_used": False,
                    "external_lookup_used": False,
                    "threat_actor_attributed": False,
                    "shared_artifact_is_not_proof": True,
                },
            )
        )

    return sorted(
        campaigns,
        key=lambda item: (
            -item.correlation_score,
            item.campaign_id,
        ),
    )
