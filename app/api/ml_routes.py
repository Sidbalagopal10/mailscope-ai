from fastapi import APIRouter, HTTPException, Query

from app.ml.classifier import (
    URLClassifierError,
    predict_url,
)


router = APIRouter(
    prefix="/ml",
    tags=["Machine Learning"],
)


@router.get("/predict-url")
def predict_url_endpoint(
    url: str = Query(
        ...,
        description=(
            "HTTP or HTTPS URL to classify"
        ),
    ),
):
    try:
        result = predict_url(url)

        return {
            "url": url,
            **result,
            "model_warning": (
                "This demonstration classifier "
                "was trained on synthetic data."
            ),
        }

    except URLClassifierError as error:
        raise HTTPException(
            status_code=503,
            detail=str(error),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                "ML URL prediction failed: "
                f"{str(error)}"
            ),
        ) from error
