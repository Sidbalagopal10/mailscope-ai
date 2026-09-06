from __future__ import annotations

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from app.evaluation.benchmark_runner import (
    BenchmarkError,
    load_latest_report,
    run_benchmark,
)


router = APIRouter(
    prefix="/evaluation",
    tags=["Accuracy Evaluation"],
)


@router.get("/latest")
def latest():
    report = load_latest_report()

    if report is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "No benchmark report exists. "
                "Run the benchmark first."
            ),
        )

    return report


@router.post("/run")
def run(
    maximum_false_positive_rate: float = Query(
        default=0.10,
        ge=0.0,
        le=1.0,
    ),
):
    try:
        return run_benchmark(
            maximum_false_positive_rate=(
                maximum_false_positive_rate
            )
        )

    except BenchmarkError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error
