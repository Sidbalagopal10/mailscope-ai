from __future__ import annotations

from app.analyst.evidence_builder import (
    build_url_evidence,
)
from app.analyst.validator import (
    validate_report,
)


def valid_payload(
    investigation_id: str,
):
    return {
        "investigation_id": (
            investigation_id
        ),

        "verdict": "suspicious",

        "confidence": 80,

        "executive_summary": (
            "Evidence indicates suspicious behavior."
        ),

        "findings": [
            {
                "title": (
                    "Impersonation detected"
                ),

                "explanation": (
                    "The deterministic engine "
                    "reported impersonation."
                ),

                "evidence_ids": [
                    "E1"
                ],

                "severity": "high",
            }
        ],

        "recommended_actions": [],

        "mitre_attack": [],

        "limitations": [],
    }


def test_valid_grounded_report():
    evidence = build_url_evidence(
        "https://microsoft-login.example/"
    )

    payload = valid_payload(
        evidence.investigation_id
    )

    errors = validate_report(
        payload=payload,
        evidence=evidence,
    )

    assert errors == []


def test_fake_evidence_reference_rejected():
    evidence = build_url_evidence(
        "https://microsoft-login.example/"
    )

    payload = valid_payload(
        evidence.investigation_id
    )

    payload[
        "findings"
    ][0][
        "evidence_ids"
    ] = [
        "E999"
    ]

    errors = validate_report(
        payload=payload,
        evidence=evidence,
    )

    assert any(
        "unknown evidence"
        in error.lower()
        for error in errors
    )


def test_uncited_finding_rejected():
    evidence = build_url_evidence(
        "https://microsoft-login.example/"
    )

    payload = valid_payload(
        evidence.investigation_id
    )

    payload[
        "findings"
    ][0][
        "evidence_ids"
    ] = []

    errors = validate_report(
        payload=payload,
        evidence=evidence,
    )

    assert any(
        "cites no evidence"
        in error.lower()
        for error in errors
    )


def test_invalid_verdict_rejected():
    evidence = build_url_evidence(
        "https://unknown.example/"
    )

    payload = valid_payload(
        evidence.investigation_id
    )

    payload[
        "verdict"
    ] = "definitely_bad"

    errors = validate_report(
        payload=payload,
        evidence=evidence,
    )

    assert (
        "Invalid verdict."
        in errors
    )
