from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from pydantic import (
    BaseModel,
    Field,
)
from sqlalchemy.orm import Session

from app.campaign_detection.repository import (
    find_campaigns_by_investigation,
)
from app.database.database import (
    get_database,
)
from app.soc_copilot.engine import (
    answer_question,
)
from app.threat_hunting.report_loader import (
    load_investigation_reports,
)


router = APIRouter(
    prefix="/soc-copilot",
    tags=["SOC Copilot"],
)


class CopilotQuestionRequest(
    BaseModel
):
    question: str = Field(
        min_length=1,
        max_length=2000,
    )


@router.post(
    "/investigation/{investigation_id}/ask"
)
def ask_soc_copilot(
    investigation_id: str,
    request: CopilotQuestionRequest,
    db: Session = Depends(
        get_database
    ),
):
    reports = (
        load_investigation_reports()
    )

    report = next(
        (
            item
            for item in reports
            if str(
                item.get(
                    "investigation_id"
                )
            )
            == investigation_id
        ),
        None,
    )

    if report is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "Investigation report not found."
            ),
        )

    campaigns = (
        find_campaigns_by_investigation(
            db,
            investigation_id,
        )
    )

    campaign_dicts = [
        (
            campaign.to_dict()
            if hasattr(
                campaign,
                "to_dict",
            )
            else campaign
        )
        for campaign in campaigns
    ]

    answer = answer_question(
        report,
        request.question,
        campaign_dicts,
    )

    return answer.to_dict()
