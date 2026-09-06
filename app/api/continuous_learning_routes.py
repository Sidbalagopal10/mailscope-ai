from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.continuous_learning.retrainer import (
    ContinuousLearningError,
    get_learning_status,
    retrain_candidate,
)


router = APIRouter(
    prefix="/continuous-learning",
    tags=["Continuous Learning"],
)


@router.get("/status")
def retrieve_status():
    return get_learning_status()


@router.post("/retrain")
def retrain_model(
    force: bool = Query(
        default=False,
    ),
):
    try:
        return retrain_candidate(
            force=force
        )

    except ContinuousLearningError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                "Continuous-learning "
                f"training failed: {error}"
            ),
        ) from error
