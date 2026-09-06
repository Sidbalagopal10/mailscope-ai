from __future__ import annotations

from app.diagnostics import (
    domain_score_trace,
)


def sample_result():
    return {
        "final_score": 85,
        "risk_level": "critical",
        "classification": (
            "likely_phishing"
        ),
        "is_phishing": True,
        "global_brand_intelligence": {
            "official_domain_match": True,
            "impersonation_detected": False,
            "risk_adjustment": 30,
        },
        "organization_intelligence": {
            "verified": True,
            "risk_adjustment": 30,
        },
        "threatfox_intelligence": {
            "matched": False,
            "risk_adjustment": 0,
        },
        "evidence_summary": {
            "ml_risk_score": 55,
        },
        "reasons": [
            "Synthetic diagnostic result."
        ],
    }


def test_score_values_are_discovered():
    findings = (
        domain_score_trace
        .flatten_relevant_values(
            sample_result()
        )
    )

    paths = {
        item[
            "path"
        ]
        for item in findings
    }

    assert (
        "root.final_score"
        in paths
    )

    assert (
        "root.global_brand_intelligence."
        "risk_adjustment"
        in paths
    )


def test_decision_flags_are_discovered():
    findings = (
        domain_score_trace
        .flatten_relevant_values(
            sample_result()
        )
    )

    flags = {
        item[
            "path"
        ]: item[
            "value"
        ]
        for item in findings
        if item[
            "kind"
        ] == "decision_flag"
    }

    assert flags[
        "root.global_brand_intelligence."
        "official_domain_match"
    ] is True

    assert flags[
        "root.global_brand_intelligence."
        "impersonation_detected"
    ] is False


def test_trace_compares_base_and_enriched(
    monkeypatch,
):
    monkeypatch.setattr(
        domain_score_trace,
        "analyze_unified_domain_profile",
        lambda *args, **kwargs: {
            **sample_result(),
            "final_score": 55,
        },
    )

    monkeypatch.setattr(
        domain_score_trace,
        "analyze_enriched_domain_profile",
        lambda *args, **kwargs: {
            **sample_result(),
            "base_unified_score": 55,
            "final_score": 85,
        },
    )

    result = (
        domain_score_trace
        .analyze_domain_trace(
            "google.com"
        )
    )

    assert result[
        "comparison"
    ][
        "base_final_score"
    ] == 55

    assert result[
        "comparison"
    ][
        "enriched_final_score"
    ] == 85

    assert result[
        "comparison"
    ][
        "enriched_wrapper_delta"
    ] == 30


def test_module_summary_preserves_identity_flags():
    summary = (
        domain_score_trace
        .extract_module_summary(
            sample_result()
        )
    )

    assert summary[
        "brand"
    ][
        "official_domain_match"
    ] is True

    assert summary[
        "brand"
    ][
        "impersonation_detected"
    ] is False
