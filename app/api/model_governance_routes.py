from __future__ import annotations

from typing import Any

from fastapi import (
    APIRouter,
    HTTPException,
)
from pydantic import BaseModel

from app.model_governance.review_calibration import (
    CalibrationGateError,
    get_gate_status,
    predict_with_candidate,
    train_and_evaluate_candidate,
)


router = APIRouter(
    prefix="/model-governance",
    tags=["Model Governance"],
)


class CandidatePredictionRequest(BaseModel):
    predicted_score: float
    predicted_risk_level: str
    predicted_classification: str


@router.get("/status")
def status():
    return get_gate_status()


@router.post("/train-candidate")
def train_candidate():
    try:
        return train_and_evaluate_candidate()

    except CalibrationGateError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error


@router.post("/candidate-prediction")
def candidate_prediction(
    request: CandidatePredictionRequest,
) -> dict[str, Any]:
    try:
        return predict_with_candidate(
            {
                "predicted_score": (
                    request.predicted_score
                ),
                "predicted_risk_level": (
                    request.predicted_risk_level
                ),
                "predicted_classification": (
                    request.predicted_classification
                ),
            }
        )

    except CalibrationGateError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error
