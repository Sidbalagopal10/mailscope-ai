from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
)
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.campaign_detection.engine import (
    correlate_reports,
)
from app.campaign_detection.repository import (
    find_campaigns_by_artifact,
    find_campaigns_by_investigation,
    get_campaign,
    list_campaigns,
    save_campaigns,
)
from app.database.database import (
    get_database,
)
from app.reports.models import (
    IOC,
    InvestigationReport,
    ReportFinding,
    TimelineEvent,
)


router = APIRouter(
    prefix="/campaigns",
    tags=["Campaign Detection"],
)


class IOCInput(BaseModel):
    type: str
    value: str
    source: str = "api"
    confidence: float | None = None


class ReportFindingInput(BaseModel):
    title: str
    explanation: str
    severity: str
    evidence_ids: list[str] = Field(
        default_factory=list
    )


class TimelineEventInput(BaseModel):
    timestamp: str
    event_type: str
    title: str
    description: str
    source: str


class InvestigationReportInput(BaseModel):
    investigation_id: str
    created_at: str

    target: str
    target_type: str

    verdict: str
    confidence: float
    severity: float
    risk_level: str

    executive_summary: str = ""

    findings: list[
        ReportFindingInput
    ] = Field(
        default_factory=list
    )

    identity: dict = Field(
        default_factory=dict
    )

    mitre_attack: list[dict[str, str]] = Field(
        default_factory=list
    )

    iocs: list[IOCInput] = Field(
        default_factory=list
    )

    timeline: list[
        TimelineEventInput
    ] = Field(
        default_factory=list
    )

    recommendations: list[str] = Field(
        default_factory=list
    )

    limitations: list[str] = Field(
        default_factory=list
    )

    evidence: dict = Field(
        default_factory=dict
    )

    analyst_model: str = "unknown"

    metadata: dict = Field(
        default_factory=dict
    )


class CorrelationRequest(BaseModel):
    reports: list[
        InvestigationReportInput
    ]


def _to_report(
    item: InvestigationReportInput,
) -> InvestigationReport:
    return InvestigationReport(
        investigation_id=(
            item.investigation_id
        ),
        created_at=item.created_at,
        target=item.target,
        target_type=item.target_type,
        verdict=item.verdict,
        confidence=float(
            item.confidence
        ),
        severity=float(
            item.severity
        ),
        risk_level=item.risk_level,
        executive_summary=(
            item.executive_summary
        ),
        findings=[
            ReportFinding(
                title=finding.title,
                explanation=(
                    finding.explanation
                ),
                severity=(
                    finding.severity
                ),
                evidence_ids=list(
                    finding.evidence_ids
                ),
            )
            for finding
            in item.findings
        ],
        identity=dict(
            item.identity
        ),
        mitre_attack=list(
            item.mitre_attack
        ),
        iocs=[
            IOC(
                type=ioc.type,
                value=ioc.value,
                source=ioc.source,
                confidence=(
                    ioc.confidence
                ),
            )
            for ioc
            in item.iocs
        ],
        timeline=[
            TimelineEvent(
                timestamp=(
                    event.timestamp
                ),
                event_type=(
                    event.event_type
                ),
                title=event.title,
                description=(
                    event.description
                ),
                source=event.source,
            )
            for event
            in item.timeline
        ],
        recommendations=list(
            item.recommendations
        ),
        limitations=list(
            item.limitations
        ),
        evidence=dict(
            item.evidence
        ),
        analyst_model=(
            item.analyst_model
        ),
        metadata=dict(
            item.metadata
        ),
    )


@router.post("/correlate")
def correlate_campaigns(
    request: CorrelationRequest,
    persist: bool = Query(
        True,
        description=(
            "Persist detected campaign candidates."
        ),
    ),
    database: Session = Depends(
        get_database
    ),
):
    reports = [
        _to_report(item)
        for item
        in request.reports
    ]

    campaigns = correlate_reports(
        reports
    )

    if persist and campaigns:
        campaigns = save_campaigns(
            database,
            campaigns,
        )

    return {
        "campaign_count": len(
            campaigns
        ),
        "campaigns": [
            campaign.to_dict()
            for campaign
            in campaigns
        ],
        "metadata": {
            "deterministic": True,
            "ai_used": False,
            "threat_actor_attributed": False,
            "persisted": bool(
                persist
            ),
        },
    }


@router.get("")
def get_campaigns(
    limit: int = Query(
        100,
        ge=1,
        le=1000,
    ),
    database: Session = Depends(
        get_database
    ),
):
    campaigns = list_campaigns(
        database,
        limit=limit,
    )

    return {
        "count": len(
            campaigns
        ),
        "campaigns": [
            campaign.to_dict()
            for campaign
            in campaigns
        ],
    }


@router.get("/investigation/{investigation_id}")
def campaigns_for_investigation(
    investigation_id: str,
    database: Session = Depends(
        get_database
    ),
):
    campaigns = (
        find_campaigns_by_investigation(
            database,
            investigation_id,
        )
    )

    return {
        "investigation_id": (
            investigation_id
        ),
        "count": len(
            campaigns
        ),
        "campaigns": [
            campaign.to_dict()
            for campaign
            in campaigns
        ],
    }


@router.get("/artifact")
def campaigns_for_artifact(
    artifact_type: str = Query(...),
    artifact_value: str = Query(...),
    database: Session = Depends(
        get_database
    ),
):
    campaigns = (
        find_campaigns_by_artifact(
            database,
            artifact_type=artifact_type,
            artifact_value=artifact_value,
        )
    )

    return {
        "artifact": {
            "type": artifact_type,
            "value": artifact_value,
        },
        "count": len(
            campaigns
        ),
        "campaigns": [
            campaign.to_dict()
            for campaign
            in campaigns
        ],
    }


@router.get("/{campaign_id}")
def campaign_by_id(
    campaign_id: str,
    database: Session = Depends(
        get_database
    ),
):
    campaign = get_campaign(
        database,
        campaign_id,
    )

    if campaign is None:
        raise HTTPException(
            status_code=404,
            detail="Campaign not found.",
        )

    return campaign.to_dict()
