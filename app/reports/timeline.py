from __future__ import annotations

from datetime import (
    datetime,
    timedelta,
    timezone,
)

from app.analyst.evidence import (
    InvestigationEvidence,
)
from app.reports.models import (
    TimelineEvent,
)


def _parse_time(
    value: str,
) -> datetime:
    try:
        return datetime.fromisoformat(
            value
        )

    except Exception:
        return datetime.now(
            timezone.utc
        )


def build_timeline(
    evidence: InvestigationEvidence,
) -> list[TimelineEvent]:
    """
    This is an investigation-processing timeline,
    not a claim about attacker activity.
    """

    start = _parse_time(
        evidence.created_at
    )

    events = [
        TimelineEvent(
            timestamp=start.isoformat(),
            event_type="evidence_collection",
            title="Investigation evidence created",
            description=(
                "The deterministic evidence package "
                "was initialized."
            ),
            source="evidence_builder",
        ),

        TimelineEvent(
            timestamp=(
                start
                + timedelta(
                    milliseconds=100
                )
            ).isoformat(),
            event_type="core_analysis",
            title="Core URL analysis completed",
            description=(
                "Core Engine v1.0 evaluated "
                "the investigation target."
            ),
            source="core-engine-v1.0",
        ),

        TimelineEvent(
            timestamp=(
                start
                + timedelta(
                    milliseconds=200
                )
            ).isoformat(),
            event_type="identity_analysis",
            title="Identity analysis completed",
            description=(
                "Organizational identity evidence "
                "was evaluated."
            ),
            source="identity_confidence_engine",
        ),
    ]

    return events
