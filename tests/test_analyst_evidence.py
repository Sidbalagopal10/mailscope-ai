from __future__ import annotations

from app.analyst.evidence_builder import (
    build_url_evidence,
)


def test_evidence_package_shape():
    result = build_url_evidence(
        "https://unknown-startup.example/"
    )

    assert (
        result.target_type
        == "url"
    )

    assert (
        result.metadata[
            "ai_used_for_evidence"
        ]
        is False
    )

    assert (
        result.metadata[
            "evidence_grounded"
        ]
        is True
    )

    assert isinstance(
        result.findings,
        list,
    )


def test_unknown_identity_remains_neutral():
    result = build_url_evidence(
        "https://unknown-startup.example/"
    )

    identity_findings = [
        finding
        for finding in result.findings
        if finding.category
        == "identity"
    ]

    assert identity_findings

    assert (
        identity_findings[
            0
        ].severity
        == "info"
    )


def test_impersonation_facts_present():
    result = build_url_evidence(
        "https://microsoft-login.example/"
    )

    text = " ".join(
        finding.title.lower()
        for finding in result.findings
    )

    assert (
        "impersonation"
        in text
    )
