from __future__ import annotations

from fastapi import (
    APIRouter,
    Query,
)

from app.analyst.evidence_builder import (
    build_url_evidence,
)
from app.analyst.evidence_store import (
    save_evidence,
)


router = APIRouter(
    prefix="/analyst",
    tags=[
        "AI Security Analyst",
    ],
)


@router.get(
    "/evidence/url"
)
def investigate_url_evidence(
    url: str = Query(
        ...,
        min_length=1,
    )
):
    evidence = build_url_evidence(
        url
    )

    path = save_evidence(
        evidence
    )

    result = evidence.to_dict()

    result[
        "saved_to"
    ] = str(
        path
    )

    return result


@router.get(
    "/report/url"
)
def investigate_url_report(
    url: str = Query(
        ...,
        min_length=1,
    )
):
    from app.analyst.analyst_engine import (
        analyze_evidence,
    )

    from app.analyst.report_store import (
        save_report,
    )

    evidence = build_url_evidence(
        url
    )

    report = analyze_evidence(
        evidence
    )

    path = save_report(
        report
    )

    result = report.to_dict()

    result[
        "saved_to"
    ] = str(
        path
    )

    return result


@router.get(
    "/investigation/url"
)
def build_full_url_investigation(
    url: str = Query(
        ...,
        min_length=1,
    )
):
    """
    Build the canonical investigation report.

    Current AI provider is selected through
    AI_ANALYST_PROVIDER.

    In development this can remain `mock`,
    requiring no paid API.
    """

    from app.reports.bundle import (
        export_report_bundle,
    )

    from app.reports.generator import (
        build_investigation_report,
    )

    evidence = build_url_evidence(
        url
    )

    report = build_investigation_report(
        evidence
    )

    artifacts = export_report_bundle(
        report
    )

    return {
        "report": report.to_dict(),
        "artifacts": artifacts,
    }

