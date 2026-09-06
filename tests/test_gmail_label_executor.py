from __future__ import annotations

import pytest

from app.gmail_actions.label_executor import (
    GmailLabelExecutionError,
    validate_plan_item,
)


def plan_item(
    *,
    level: str = "high",
    labels=None,
):
    return {
        "message_id": "message-123",
        "risk_level": level,
        "proposed_labels": (
            labels
            if labels is not None
            else [
                "PHISHING_HIGH",
                "PROCESSED",
            ]
        ),
    }


def test_high_risk_plan_is_valid():
    validate_plan_item(
        plan_item()
    )


def test_low_risk_blocked_by_default():
    with pytest.raises(
        GmailLabelExecutionError
    ):
        validate_plan_item(
            plan_item(
                level="low",
                labels=[
                    "PROCESSED"
                ],
            )
        )


def test_low_risk_can_be_explicitly_allowed():
    validate_plan_item(
        plan_item(
            level="low",
            labels=[
                "PROCESSED"
            ],
        ),
        allow_low_risk=True,
    )


def test_system_label_is_blocked():
    with pytest.raises(
        GmailLabelExecutionError
    ):
        validate_plan_item(
            plan_item(
                labels=[
                    "PHISHING_HIGH",
                    "TRASH",
                ],
            )
        )


def test_unknown_label_is_blocked():
    with pytest.raises(
        GmailLabelExecutionError
    ):
        validate_plan_item(
            plan_item(
                labels=[
                    "UNAPPROVED_LABEL"
                ],
            )
        )


def test_missing_message_id_is_blocked():
    item = plan_item()
    item["message_id"] = ""

    with pytest.raises(
        GmailLabelExecutionError
    ):
        validate_plan_item(
            item
        )
