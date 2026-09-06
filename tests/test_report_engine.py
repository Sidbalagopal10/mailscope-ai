from __future__ import annotations

from pathlib import Path

from app.analyst.evidence_builder import (
    build_url_evidence,
)
from app.reports.ioc_extractor import (
    extract_iocs,
)
from app.reports.timeline import (
    build_timeline,
)


def test_ioc_extraction():
    evidence = build_url_evidence(
        "https://microsoft-login.example/"
    )

    iocs = extract_iocs(
        evidence
    )

    values = {
        (
            item.type,
            item.value,
        )
        for item in iocs
    }

    assert (
        "url",
        "https://microsoft-login.example/",
    ) in values

    assert (
        "hostname",
        "microsoft-login.example",
    ) in values


def test_timeline_exists():
    evidence = build_url_evidence(
        "https://unknown-startup.example/"
    )

    timeline = build_timeline(
        evidence
    )

    assert len(
        timeline
    ) >= 3

    assert (
        timeline[
            0
        ].event_type
        == "evidence_collection"
    )
