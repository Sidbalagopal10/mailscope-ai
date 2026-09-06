from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
    status,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

from app.feedback.service import (
    FeedbackError,
    delete_feedback,
    get_feedback_by_id,
    get_feedback_summary,
    list_feedback,
    save_feedback,
)


router = APIRouter(
    prefix="/feedback",
    tags=["Verified Feedback"],
)


class FeedbackCreateRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid"
    )

    url: str = Field(
        ...,
        min_length=4,
        max_length=4096,
    )

    predicted_label: int = Field(
        ...,
        ge=0,
        le=1,
        description=(
            "0 for benign, 1 for phishing."
        ),
    )

    predicted_probability: Optional[
        float
    ] = Field(
        default=None,
        ge=0,
        le=1,
    )

    final_score: Optional[float] = Field(
        default=None,
        ge=0,
        le=100,
    )

    risk_level: Optional[str] = Field(
        default=None,
        max_length=30,
    )

    is_prediction_correct: bool

    confirmed_label: int = Field(
        ...,
        ge=0,
        le=1,
        description=(
            "Human-confirmed label: "
            "0 for benign, 1 for phishing."
        ),
    )

    model_version: Optional[str] = Field(
        default=None,
        max_length=100,
    )

    model_type: Optional[str] = Field(
        default=None,
        max_length=100,
    )

    source: str = Field(
        default="dashboard",
        min_length=1,
        max_length=100,
    )

    notes: Optional[str] = Field(
        default=None,
        max_length=2000,
    )

    analysis_snapshot: Optional[
        Dict[str, Any]
    ] = None

    @model_validator(mode="after")
    def validate_confirmed_label(
        self,
    ):
        expected_label = (
            self.predicted_label
            if self.is_prediction_correct
            else 1 - self.predicted_label
        )

        if (
            self.confirmed_label
            != expected_label
        ):
            raise ValueError(
                "confirmed_label does not match "
                "is_prediction_correct."
            )

        return self


class FeedbackResponse(BaseModel):
    id: int
    url: str
    predicted_label: int
    predicted_classification: str
    predicted_probability: Optional[float]
    final_score: Optional[float]
    risk_level: Optional[str]
    is_prediction_correct: bool
    confirmed_label: int
    confirmed_classification: str
    model_version: Optional[str]
    model_type: Optional[str]
    source: str
    notes: Optional[str]
    analysis_snapshot: Optional[
        Dict[str, Any]
    ]
    created_at: str
    updated_at: str


@router.post(
    "",
    response_model=FeedbackResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_feedback(
    request: FeedbackCreateRequest,
):
    try:
        return save_feedback(
            **request.model_dump()
        )

    except FeedbackError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error


@router.get(
    "",
    response_model=List[FeedbackResponse],
)
def retrieve_feedback(
    limit: int = Query(
        default=100,
        ge=1,
        le=1000,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    confirmed_label: Optional[
        int
    ] = Query(
        default=None,
        ge=0,
        le=1,
    ),
):
    try:
        return list_feedback(
            limit=limit,
            offset=offset,
            confirmed_label=(
                confirmed_label
            ),
        )

    except FeedbackError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error


@router.get("/summary")
def retrieve_feedback_summary():
    return get_feedback_summary()


@router.get(
    "/{feedback_id}",
    response_model=FeedbackResponse,
)
def retrieve_feedback_record(
    feedback_id: int,
):
    record = get_feedback_by_id(
        feedback_id
    )

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Feedback record not found.",
        )

    return record


@router.delete(
    "/{feedback_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def remove_feedback(
    feedback_id: int,
):
    deleted = delete_feedback(
        feedback_id
    )

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Feedback record not found.",
        )

    return None
