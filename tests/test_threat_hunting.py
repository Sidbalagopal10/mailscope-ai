import json
from pathlib import Path

import pytest

from app.threat_hunting.engine import (
    hunt_reports,
)


def write_report(
    root: Path,
    investigation_id: str,
    *,
    target: str,
    iocs: list[dict],
    verdict: str = "likely_phishing",
    severity: float = 6.0,
):
    folder = (
        root
        / investigation_id
    )

    folder.mkdir(
        parents=True,
        exist_ok=True,
    )

    payload = {
        "investigation_id": (
            investigation_id
        ),
        "created_at": (
            "2026-09-06T00:00:00Z"
        ),
        "target": target,
        "target_type": "url",
        "verdict": verdict,
        "confidence": 88,
        "severity": severity,
        "risk_level": "MODERATE",
        "identity": {},
        "iocs": iocs,
    }

    (
        folder
        / f"{investigation_id}.json"
    ).write_text(
        json.dumps(
            payload
        ),
        encoding="utf-8",
    )


def test_domain_hunt_finds_related_reports(
    tmp_path,
):
    write_report(
        tmp_path,
        "inv-a",
        target=(
            "https://evil.example/login"
        ),
        iocs=[
            {
                "type": "domain",
                "value": (
                    "evil.example"
                ),
                "source": "ioc",
            }
        ],
    )

    write_report(
        tmp_path,
        "inv-b",
        target=(
            "https://evil.example/pay"
        ),
        iocs=[
            {
                "type": "domain",
                "value": (
                    "evil.example"
                ),
                "source": "ioc",
            }
        ],
    )

    result = hunt_reports(
        "evil.example",
        "domain",
        tmp_path,
    )

    assert len(
        result.matches
    ) == 2


def test_domain_matching_is_case_insensitive(
    tmp_path,
):
    write_report(
        tmp_path,
        "inv-a",
        target=(
            "https://example.com/"
        ),
        iocs=[
            {
                "type": "domain",
                "value": (
                    "Example.COM."
                ),
                "source": "ioc",
            }
        ],
    )

    result = hunt_reports(
        "example.com",
        "domain",
        tmp_path,
    )

    assert len(
        result.matches
    ) == 1


def test_ip_exact_match(
    tmp_path,
):
    write_report(
        tmp_path,
        "inv-a",
        target=(
            "https://example.com/"
        ),
        iocs=[
            {
                "type": "ip",
                "value": "1.2.3.4",
                "source": "ioc",
            }
        ],
    )

    result = hunt_reports(
        "1.2.3.4",
        "ip",
        tmp_path,
    )

    assert len(
        result.matches
    ) == 1


def test_unrelated_observable_returns_zero(
    tmp_path,
):
    write_report(
        tmp_path,
        "inv-a",
        target=(
            "https://example.com/"
        ),
        iocs=[
            {
                "type": "domain",
                "value": (
                    "example.com"
                ),
                "source": "ioc",
            }
        ],
    )

    result = hunt_reports(
        "other.example",
        "domain",
        tmp_path,
    )

    assert result.matches == []


def test_invalid_json_is_ignored(
    tmp_path,
):
    (
        tmp_path
        / "broken.json"
    ).write_text(
        "{broken",
        encoding="utf-8",
    )

    result = hunt_reports(
        "anything",
        "domain",
        tmp_path,
    )

    assert (
        result.scanned_reports
        == 0
    )


def test_no_ai_or_external_lookup(
    tmp_path,
):
    result = hunt_reports(
        "example.com",
        "domain",
        tmp_path,
    )

    assert (
        result.metadata[
            "deterministic"
        ]
        is True
    )

    assert (
        result.metadata[
            "ai_used"
        ]
        is False
    )

    assert (
        result.metadata[
            "external_lookup_used"
        ]
        is False
    )

    assert (
        result.metadata[
            "verdict_modified"
        ]
        is False
    )


def test_unsupported_type_rejected(
    tmp_path,
):
    with pytest.raises(
        ValueError
    ):
        hunt_reports(
            "x",
            "unsupported",
            tmp_path,
        )
