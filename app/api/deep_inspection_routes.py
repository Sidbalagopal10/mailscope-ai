from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
)
from pydantic import (
    BaseModel,
    Field,
)

from app.link_intelligence.deep_inspector import (
    DeepInspectionError,
    inspect_url,
)


router = APIRouter(
    prefix="/deep-inspection",
    tags=["Safe Deep Link Inspection"],
)


class DeepInspectionRequest(BaseModel):
    url: str = Field(
        min_length=8,
        max_length=4096,
    )


@router.post("/inspect")
def inspect_link(
    request: DeepInspectionRequest,
):
    try:
        return inspect_url(
            request.url
        )

    except DeepInspectionError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                "Deep-link inspection failed: "
                f"{error}"
            ),
        ) from error
