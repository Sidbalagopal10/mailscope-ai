from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.campaign_detection.database_models import (
    CampaignRecord,
)
from app.campaign_detection.models import (
    CampaignCandidate,
    CampaignRelationship,
    CorrelationArtifact,
)


def _dump(
    value: Any,
) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        default=str,
    )


def _load(
    value: str | None,
    default: Any,
) -> Any:
    if not value:
        return default

    try:
        return json.loads(value)
    except (
        json.JSONDecodeError,
        TypeError,
    ):
        return default


def _candidate_from_record(
    record: CampaignRecord,
) -> CampaignCandidate:
    relationships = [
        CampaignRelationship(
            investigation_a=str(
                item.get(
                    "investigation_a",
                    "",
                )
            ),
            investigation_b=str(
                item.get(
                    "investigation_b",
                    "",
                )
            ),
            artifact_type=str(
                item.get(
                    "artifact_type",
                    "",
                )
            ),
            artifact_value=str(
                item.get(
                    "artifact_value",
                    "",
                )
            ),
            strength=float(
                item.get(
                    "strength",
                    0.0,
                )
            ),
            rationale=str(
                item.get(
                    "rationale",
                    "",
                )
            ),
        )
        for item in _load(
            record.relationships_json,
            [],
        )
    ]

    shared_artifacts = [
        CorrelationArtifact(
            type=str(
                item.get(
                    "type",
                    "",
                )
            ),
            value=str(
                item.get(
                    "value",
                    "",
                )
            ),
            source=str(
                item.get(
                    "source",
                    "",
                )
            ),
            confidence=(
                float(
                    item[
                        "confidence"
                    ]
                )
                if item.get(
                    "confidence"
                )
                is not None
                else None
            ),
        )
        for item in _load(
            record.shared_artifacts_json,
            [],
        )
    ]

    return CampaignCandidate(
        campaign_id=(
            record.campaign_id
        ),
        investigation_ids=[
            str(item)
            for item in _load(
                record.investigation_ids_json,
                [],
            )
        ],
        relationships=relationships,
        shared_artifacts=shared_artifacts,
        correlation_score=float(
            record.correlation_score
        ),
        strength=str(
            record.strength
        ),
        first_seen=(
            record.first_seen
        ),
        last_seen=(
            record.last_seen
        ),
        metadata=dict(
            _load(
                record.metadata_json,
                {},
            )
        ),
    )


def save_campaign(
    database: Session,
    campaign: CampaignCandidate,
) -> CampaignCandidate:
    record = database.get(
        CampaignRecord,
        campaign.campaign_id,
    )

    payload = {
        "investigation_ids_json": _dump(
            campaign.investigation_ids
        ),
        "relationships_json": _dump(
            [
                item.to_dict()
                for item
                in campaign.relationships
            ]
        ),
        "shared_artifacts_json": _dump(
            [
                item.to_dict()
                for item
                in campaign.shared_artifacts
            ]
        ),
        "correlation_score": float(
            campaign.correlation_score
        ),
        "strength": (
            campaign.strength
        ),
        "first_seen": (
            campaign.first_seen
        ),
        "last_seen": (
            campaign.last_seen
        ),
        "metadata_json": _dump(
            campaign.metadata
        ),
    }

    if record is None:
        record = CampaignRecord(
            campaign_id=(
                campaign.campaign_id
            ),
            **payload,
        )

        database.add(
            record
        )

    else:
        for key, value in (
            payload.items()
        ):
            setattr(
                record,
                key,
                value,
            )

    database.commit()
    database.refresh(
        record
    )

    return _candidate_from_record(
        record
    )


def save_campaigns(
    database: Session,
    campaigns: list[
        CampaignCandidate
    ],
) -> list[
    CampaignCandidate
]:
    return [
        save_campaign(
            database,
            campaign,
        )
        for campaign
        in campaigns
    ]


def get_campaign(
    database: Session,
    campaign_id: str,
) -> CampaignCandidate | None:
    record = database.get(
        CampaignRecord,
        campaign_id,
    )

    if record is None:
        return None

    return _candidate_from_record(
        record
    )


def list_campaigns(
    database: Session,
    *,
    limit: int = 100,
) -> list[CampaignCandidate]:
    records = (
        database.query(
            CampaignRecord
        )
        .order_by(
            CampaignRecord.updated_at.desc()
        )
        .limit(
            limit
        )
        .all()
    )

    return [
        _candidate_from_record(
            record
        )
        for record in records
    ]


def find_campaigns_by_investigation(
    database: Session,
    investigation_id: str,
) -> list[CampaignCandidate]:
    target = str(
        investigation_id
    )

    return [
        campaign
        for campaign
        in list_campaigns(
            database,
            limit=10000,
        )
        if target
        in campaign.investigation_ids
    ]


def find_campaigns_by_artifact(
    database: Session,
    *,
    artifact_type: str,
    artifact_value: str,
) -> list[CampaignCandidate]:
    wanted_type = str(
        artifact_type
    ).strip().lower()

    wanted_value = str(
        artifact_value
    ).strip().lower()

    matches = []

    for campaign in list_campaigns(
        database,
        limit=10000,
    ):
        if any(
            artifact.type.lower()
            == wanted_type
            and
            artifact.value.lower()
            == wanted_value

            for artifact
            in campaign.shared_artifacts
        ):
            matches.append(
                campaign
            )

    return matches
