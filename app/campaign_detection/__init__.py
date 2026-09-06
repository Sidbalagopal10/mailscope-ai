"""
Deterministic campaign correlation.

Campaign relationships are created only from evidence-backed
artifacts already present in canonical InvestigationReport objects.
"""

from app.campaign_detection.engine import correlate_reports
from app.campaign_detection.models import (
    CampaignCandidate,
    CampaignRelationship,
    CorrelationArtifact,
)

__all__ = [
    "CampaignCandidate",
    "CampaignRelationship",
    "CorrelationArtifact",
    "correlate_reports",
]
