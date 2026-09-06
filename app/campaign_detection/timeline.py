from __future__ import annotations

from dataclasses import (
    asdict,
    dataclass,
)

from app.campaign_detection.models import (
    CampaignCandidate,
)
from app.reports.models import (
    InvestigationReport,
)


@dataclass(frozen=True)
class CampaignTimelineEvent:
    timestamp: str
    event_type: str
    investigation_id: str
    title: str
    description: str

    def to_dict(self):
        return asdict(self)


def build_campaign_timeline(
    campaign: CampaignCandidate,
    reports: list[
        InvestigationReport
    ],
) -> list[
    CampaignTimelineEvent
]:
    reports_by_id = {
        report.investigation_id: report
        for report in reports
    }

    events: list[
        CampaignTimelineEvent
    ] = []

    for investigation_id in (
        campaign.investigation_ids
    ):
        report = reports_by_id.get(
            investigation_id
        )

        if report is None:
            continue

        events.append(
            CampaignTimelineEvent(
                timestamp=(
                    report.created_at
                ),
                event_type=(
                    "investigation_observed"
                ),
                investigation_id=(
                    investigation_id
                ),
                title=(
                    "Related investigation observed"
                ),
                description=(
                    "An investigation associated with "
                    "this deterministic campaign "
                    "candidate was observed."
                ),
            )
        )

    return sorted(
        events,
        key=lambda item: (
            item.timestamp,
            item.investigation_id,
        ),
    )
