from __future__ import annotations

from app.gmail_actions.label_planner import (
    build_label_plan,
    build_label_plan_for_message,
    proposed_labels_for_level,
)


def message(
    *,
    level: str,
    score: float,
    authenticated_normal_urgency: bool = False,
    authentication_verdict: str = "authenticated",
    deep_results=None,
):
    return {
        "message_id": "message-1",
        "thread_id": "thread-1",
        "subject": "Test message",
        "sender_address": "sender@example.com",
        "contextual_decision": {
            "risk_score": score,
            "risk_level": level,
            "classification": (
                "likely_legitimate"
                if level == "low"
                else "needs_review"
            ),
            "authenticated_normal_urgency": (
                authenticated_normal_urgency
            ),
            "authentication_evidence": {
                "verdict": (
                    authentication_verdict
                )
            },
            "suspicious_signals": [],
            "reasons": [],
        },
        "deep_link_analysis": {
            "results": (
                deep_results
                or []
            )
        },
    }


def test_low_risk_gets_processed_label():
    assert proposed_labels_for_level(
        "low"
    ) == [
        "PROCESSED"
    ]


def test_moderate_gets_review_label():
    labels = proposed_labels_for_level(
        "moderate"
    )

    assert "PHISHING_MODERATE" in labels
    assert "PROCESSED" in labels


def test_high_gets_high_label():
    labels = proposed_labels_for_level(
        "high"
    )

    assert "PHISHING_HIGH" in labels


def test_authenticated_normal_urgency_does_not_require_review():
    plan = build_label_plan_for_message(
        message(
            level="low",
            score=5,
            authenticated_normal_urgency=True,
        )
    )

    assert not plan[
        "human_review_required"
    ]

    assert plan[
        "proposed_escalation"
    ] == "none"


def test_critical_proposes_quarantine():
    plan = build_label_plan_for_message(
        message(
            level="critical",
            score=95,
        )
    )

    assert plan[
        "proposed_escalation"
    ] == "propose_quarantine"

    assert plan[
        "human_review_required"
    ]


def test_threatfox_match_requires_review():
    plan = build_label_plan_for_message(
        message(
            level="low",
            score=10,
            deep_results=[
                {
                    "threatfox_intelligence": {
                        "matched": True
                    },
                    "global_brand_intelligence": {
                        "impersonation_detected": False
                    },
                }
            ],
        )
    )

    assert plan[
        "threat_match"
    ]

    assert plan[
        "human_review_required"
    ]


def test_dry_run_never_modifies_gmail():
    plan = build_label_plan(
        {
            "messages": [
                message(
                    level="high",
                    score=75,
                )
            ]
        }
    )

    assert plan[
        "dry_run"
    ]

    assert not plan[
        "gmail_modified"
    ]

    assert plan[
        "plans"
    ][0][
        "dry_run"
    ]

    assert not plan[
        "plans"
    ][0][
        "gmail_modified"
    ]
