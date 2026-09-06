from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPORT_PATH = Path(
    "data/gmail_actions/latest_label_plan.json"
)


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def normalize_risk_level(
    value: str | None,
) -> str:
    normalized = str(
        value or "low"
    ).strip().lower()

    if normalized not in {
        "low",
        "moderate",
        "high",
        "critical",
    }:
        return "low"

    return normalized


def proposed_labels_for_level(
    risk_level: str,
) -> list[str]:
    normalized = normalize_risk_level(
        risk_level
    )

    mapping = {
        "low": [
            "PROCESSED",
        ],
        "moderate": [
            "PHISHING_MODERATE",
            "PROCESSED",
        ],
        "high": [
            "PHISHING_HIGH",
            "PROCESSED",
        ],
        "critical": [
            "PHISHING_HIGH",
            "PROCESSED",
        ],
    }

    return mapping[
        normalized
    ]


def escalation_action(
    risk_level: str,
) -> str:
    normalized = normalize_risk_level(
        risk_level
    )

    if normalized == "critical":
        return "propose_quarantine"

    if normalized == "high":
        return "propose_warning"

    if normalized == "moderate":
        return "propose_review"

    return "none"


def should_require_human_review(
    *,
    risk_level: str,
    authenticated_normal_urgency: bool,
    threat_match: bool,
    brand_impersonation: bool,
    authentication_failed: bool,
) -> bool:
    normalized = normalize_risk_level(
        risk_level
    )

    if authenticated_normal_urgency:
        return False

    return bool(
        normalized
        in {
            "moderate",
            "high",
            "critical",
        }
        or threat_match
        or brand_impersonation
        or authentication_failed
    )


def build_label_plan_for_message(
    message: dict[str, Any],
) -> dict[str, Any]:
    decision = message.get(
        "contextual_decision",
        {},
    )

    risk_level = normalize_risk_level(
        decision.get(
            "risk_level"
        )
    )

    authentication_evidence = decision.get(
        "authentication_evidence",
        {},
    )

    deep_analysis = message.get(
        "deep_link_analysis",
        {},
    )

    deep_results = deep_analysis.get(
        "results",
        [],
    )

    threat_match = any(
        bool(
            result.get(
                "threatfox_intelligence",
                {},
            ).get(
                "matched",
                False,
            )
        )
        for result in deep_results
        if isinstance(
            result,
            dict,
        )
    )

    brand_impersonation = any(
        bool(
            result.get(
                "global_brand_intelligence",
                {},
            ).get(
                "impersonation_detected",
                False,
            )
        )
        for result in deep_results
        if isinstance(
            result,
            dict,
        )
    )

    authentication_failed = bool(
        authentication_evidence.get(
            "verdict"
        )
        in {
            "authentication_failed",
            "dmarc_failed",
        }
    )

    authenticated_normal_urgency = bool(
        decision.get(
            "authenticated_normal_urgency",
            False,
        )
    )

    labels = proposed_labels_for_level(
        risk_level
    )

    human_review = should_require_human_review(
        risk_level=risk_level,
        authenticated_normal_urgency=(
            authenticated_normal_urgency
        ),
        threat_match=threat_match,
        brand_impersonation=(
            brand_impersonation
        ),
        authentication_failed=(
            authentication_failed
        ),
    )

    reasons = list(
        decision.get(
            "suspicious_signals",
            [],
        )
    )

    reasons.extend(
        decision.get(
            "reasons",
            [],
        )
    )

    if threat_match:
        reasons.append(
            "A deep-analyzed URL matched ThreatFox."
        )

    if brand_impersonation:
        reasons.append(
            "A deep-analyzed URL appears to impersonate "
            "an indexed brand."
        )

    if authentication_failed:
        reasons.append(
            "Sender authentication produced a failed verdict."
        )

    if authenticated_normal_urgency:
        reasons.append(
            "Authenticated academic or business urgency was "
            "recognized as normal context."
        )

    return {
        "message_id": message.get(
            "message_id"
        ),
        "thread_id": message.get(
            "thread_id"
        ),
        "subject": message.get(
            "subject"
        ),
        "sender_address": message.get(
            "sender_address"
        ),
        "risk_score": decision.get(
            "risk_score",
            0,
        ),
        "risk_level": risk_level,
        "classification": decision.get(
            "classification"
        ),
        "proposed_labels": labels,
        "proposed_escalation": (
            escalation_action(
                risk_level
            )
        ),
        "human_review_required": (
            human_review
        ),
        "authenticated_normal_urgency": (
            authenticated_normal_urgency
        ),
        "threat_match": threat_match,
        "brand_impersonation": (
            brand_impersonation
        ),
        "authentication_failed": (
            authentication_failed
        ),
        "reasons": reasons,
        "dry_run": True,
        "gmail_modified": False,
    }


def build_label_plan(
    observation_report: dict[str, Any],
) -> dict[str, Any]:
    messages = observation_report.get(
        "messages",
        [],
    )

    plans = [
        build_label_plan_for_message(
            message
        )
        for message in messages
        if isinstance(
            message,
            dict,
        )
    ]

    summary = {
        "messages_planned": len(
            plans
        ),
        "low": sum(
            1
            for plan in plans
            if plan[
                "risk_level"
            ]
            == "low"
        ),
        "moderate": sum(
            1
            for plan in plans
            if plan[
                "risk_level"
            ]
            == "moderate"
        ),
        "high": sum(
            1
            for plan in plans
            if plan[
                "risk_level"
            ]
            == "high"
        ),
        "critical": sum(
            1
            for plan in plans
            if plan[
                "risk_level"
            ]
            == "critical"
        ),
        "human_review_required": sum(
            1
            for plan in plans
            if plan[
                "human_review_required"
            ]
        ),
        "proposed_quarantine": sum(
            1
            for plan in plans
            if plan[
                "proposed_escalation"
            ]
            == "propose_quarantine"
        ),
    }

    return {
        "created_at": utc_now(),
        "dry_run": True,
        "gmail_modified": False,
        "summary": summary,
        "plans": plans,
        "safety_notice": (
            "This report is advisory only. No Gmail labels, "
            "message state, or mailbox contents were changed."
        ),
    }


def save_label_plan(
    plan: dict[str, Any],
) -> Path:
    REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT_PATH.write_text(
        json.dumps(
            plan,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    return REPORT_PATH
