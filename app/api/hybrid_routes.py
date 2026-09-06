from urllib.parse import urlparse

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.detection.hybrid_detector import (
    analyze_url_hybrid,
)


router = APIRouter(
    prefix="/hybrid",
    tags=["Hybrid Detection"],
)


def validate_url(url: str) -> str:
    cleaned_url = url.strip()

    if not cleaned_url:
        raise HTTPException(
            status_code=422,
            detail="URL cannot be empty.",
        )

    try:
        parsed_url = urlparse(
            cleaned_url
        )
    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail="The URL is malformed.",
        ) from error

    if parsed_url.scheme.lower() not in {
        "http",
        "https",
    }:
        raise HTTPException(
            status_code=422,
            detail=(
                "Only HTTP and HTTPS URLs "
                "can be analyzed."
            ),
        )

    if not parsed_url.hostname:
        raise HTTPException(
            status_code=422,
            detail=(
                "The URL must contain a hostname."
            ),
        )

    return cleaned_url


@router.get("/analyze-url")
def analyze_url_endpoint(
    url: str = Query(
        ...,
        description=(
            "HTTP or HTTPS URL to analyze "
            "using heuristic and ML detection."
        ),
    ),
):
    cleaned_url = validate_url(url)

    try:
        return analyze_url_hybrid(
            cleaned_url
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                "Hybrid URL analysis failed: "
                f"{error}"
            ),
        ) from error
