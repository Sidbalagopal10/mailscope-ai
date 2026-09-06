from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


MODIFY_SCOPE = (
    "https://www.googleapis.com/auth/gmail.modify"
)

TOKEN_CANDIDATES = [
    Path("token.json"),
    Path("app/gmail/token.json"),
]

PLAN_PATH = Path(
    "data/gmail_actions/latest_label_plan.json"
)

AUDIT_PATH = Path(
    "data/gmail_actions/label_execution_audit.jsonl"
)

ALLOWED_LABELS = {
    "PROCESSED",
    "PHISHING_MODERATE",
    "PHISHING_HIGH",
}

BLOCKED_SYSTEM_LABELS = {
    "INBOX",
    "SPAM",
    "TRASH",
    "UNREAD",
    "STARRED",
    "IMPORTANT",
    "SENT",
    "DRAFT",
}


class GmailLabelExecutionError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def find_token_path() -> Path:
    for path in TOKEN_CANDIDATES:
        if path.exists():
            return path

    raise GmailLabelExecutionError(
        "token.json was not found."
    )


def get_modify_service():
    token_path = find_token_path()

    credentials = (
        Credentials.from_authorized_user_file(
            str(token_path),
            [MODIFY_SCOPE],
        )
    )

    granted_scopes = set(
        credentials.scopes
        or []
    )

    if MODIFY_SCOPE not in granted_scopes:
        raise GmailLabelExecutionError(
            "The Gmail token does not contain gmail.modify. "
            "Reauthorize using the modify scope."
        )

    if (
        credentials.expired
        and credentials.refresh_token
    ):
        credentials.refresh(
            Request()
        )

        token_path.write_text(
            credentials.to_json(),
            encoding="utf-8",
        )

    if not credentials.valid:
        raise GmailLabelExecutionError(
            "Gmail OAuth credentials are invalid."
        )

    return build(
        "gmail",
        "v1",
        credentials=credentials,
        cache_discovery=False,
    )


def load_latest_plan() -> dict[str, Any]:
    if not PLAN_PATH.exists():
        raise GmailLabelExecutionError(
            "No label plan exists. Generate the dry-run plan first."
        )

    try:
        return json.loads(
            PLAN_PATH.read_text(
                encoding="utf-8"
            )
        )

    except json.JSONDecodeError as error:
        raise GmailLabelExecutionError(
            "The saved label plan contains invalid JSON."
        ) from error


def list_label_map(
    service,
) -> dict[str, str]:
    response = (
        service.users()
        .labels()
        .list(
            userId="me"
        )
        .execute()
    )

    return {
        str(item.get("name")): str(
            item.get("id")
        )
        for item in response.get(
            "labels",
            []
        )
        if (
            item.get("name")
            and item.get("id")
        )
    }


def ensure_user_label(
    service,
    label_name: str,
) -> str:
    normalized = str(
        label_name
    ).strip()

    if normalized not in ALLOWED_LABELS:
        raise GmailLabelExecutionError(
            f"Label is not permitted: {normalized}"
        )

    label_map = list_label_map(
        service
    )

    existing = label_map.get(
        normalized
    )

    if existing:
        return existing

    created = (
        service.users()
        .labels()
        .create(
            userId="me",
            body={
                "name": normalized,
                "messageListVisibility": "show",
                "labelListVisibility": "labelShow",
            },
        )
        .execute()
    )

    label_id = created.get(
        "id"
    )

    if not label_id:
        raise GmailLabelExecutionError(
            f"Could not create label: {normalized}"
        )

    return str(
        label_id
    )


def validate_plan_item(
    item: dict[str, Any],
    *,
    allow_low_risk: bool = False,
) -> None:
    message_id = str(
        item.get(
            "message_id",
            "",
        )
    ).strip()

    if not message_id:
        raise GmailLabelExecutionError(
            "Plan item has no Gmail message ID."
        )

    risk_level = str(
        item.get(
            "risk_level",
            "",
        )
    ).lower()

    if (
        risk_level == "low"
        and not allow_low_risk
    ):
        raise GmailLabelExecutionError(
            "Low-risk messages are blocked from real labeling "
            "unless explicitly permitted."
        )

    proposed_labels = item.get(
        "proposed_labels",
        [],
    )

    if not isinstance(
        proposed_labels,
        list,
    ):
        raise GmailLabelExecutionError(
            "Proposed labels must be a list."
        )

    prohibited = (
        set(
            proposed_labels
        )
        & BLOCKED_SYSTEM_LABELS
    )

    if prohibited:
        raise GmailLabelExecutionError(
            "System-label changes are prohibited: "
            + ", ".join(
                sorted(
                    prohibited
                )
            )
        )

    unknown = (
        set(
            proposed_labels
        )
        - ALLOWED_LABELS
    )

    if unknown:
        raise GmailLabelExecutionError(
            "Unapproved labels were requested: "
            + ", ".join(
                sorted(
                    unknown
                )
            )
        )


def append_audit_record(
    record: dict[str, Any],
) -> None:
    AUDIT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with AUDIT_PATH.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(
                record,
                sort_keys=True,
            )
            + "\n"
        )


def execute_label_plan(
    *,
    message_ids: list[str],
    confirmation: str,
    allow_low_risk: bool = False,
) -> dict[str, Any]:
    if confirmation != "APPLY LABELS":
        raise GmailLabelExecutionError(
            "Confirmation phrase must exactly equal APPLY LABELS."
        )

    selected_ids = {
        str(
            value
        ).strip()
        for value in message_ids
        if str(
            value
        ).strip()
    }

    if not selected_ids:
        raise GmailLabelExecutionError(
            "Select at least one message."
        )

    if len(selected_ids) > 25:
        raise GmailLabelExecutionError(
            "A maximum of 25 messages can be labeled per run."
        )

    plan = load_latest_plan()

    plan_items = {
        str(
            item.get(
                "message_id"
            )
        ): item
        for item in plan.get(
            "plans",
            []
        )
        if item.get(
            "message_id"
        )
    }

    missing = (
        selected_ids
        - set(
            plan_items
        )
    )

    if missing:
        raise GmailLabelExecutionError(
            "Selected messages are absent from the latest plan: "
            + ", ".join(
                sorted(
                    missing
                )
            )
        )

    service = get_modify_service()

    results: list[dict[str, Any]] = []

    for message_id in sorted(
        selected_ids
    ):
        item = plan_items[
            message_id
        ]

        try:
            validate_plan_item(
                item,
                allow_low_risk=allow_low_risk,
            )

            label_names = [
                label
                for label in item.get(
                    "proposed_labels",
                    []
                )
                if label in ALLOWED_LABELS
            ]

            label_ids = [
                ensure_user_label(
                    service,
                    label,
                )
                for label in label_names
            ]

            before = (
                service.users()
                .messages()
                .get(
                    userId="me",
                    id=message_id,
                    format="minimal",
                )
                .execute()
            )

            before_label_ids = list(
                before.get(
                    "labelIds",
                    []
                )
            )

            modified = (
                service.users()
                .messages()
                .modify(
                    userId="me",
                    id=message_id,
                    body={
                        "addLabelIds": label_ids,
                        "removeLabelIds": [],
                    },
                )
                .execute()
            )

            result = {
                "message_id": message_id,
                "subject": item.get(
                    "subject"
                ),
                "sender_address": item.get(
                    "sender_address"
                ),
                "risk_score": item.get(
                    "risk_score"
                ),
                "risk_level": item.get(
                    "risk_level"
                ),
                "applied_label_names": (
                    label_names
                ),
                "applied_label_ids": (
                    label_ids
                ),
                "before_label_ids": (
                    before_label_ids
                ),
                "after_label_ids": (
                    modified.get(
                        "labelIds",
                        []
                    )
                ),
                "success": True,
                "error": None,
                "executed_at": utc_now(),
            }

        except Exception as error:
            result = {
                "message_id": message_id,
                "subject": item.get(
                    "subject"
                ),
                "sender_address": item.get(
                    "sender_address"
                ),
                "risk_score": item.get(
                    "risk_score"
                ),
                "risk_level": item.get(
                    "risk_level"
                ),
                "applied_label_names": [],
                "applied_label_ids": [],
                "before_label_ids": [],
                "after_label_ids": [],
                "success": False,
                "error": str(
                    error
                ),
                "executed_at": utc_now(),
            }

        append_audit_record(
            {
                "event": "apply_labels",
                **result,
            }
        )

        results.append(
            result
        )

    return {
        "executed_at": utc_now(),
        "requested": len(
            selected_ids
        ),
        "successful": sum(
            1
            for result in results
            if result[
                "success"
            ]
        ),
        "failed": sum(
            1
            for result in results
            if not result[
                "success"
            ]
        ),
        "gmail_modified": any(
            result[
                "success"
            ]
            for result in results
        ),
        "results": results,
        "safety_controls": {
            "delete_permitted": False,
            "archive_permitted": False,
            "remove_inbox_permitted": False,
            "spam_permitted": False,
            "label_only": True,
        },
    }


def undo_execution(
    *,
    execution_results: list[
        dict[str, Any]
    ],
    confirmation: str,
) -> dict[str, Any]:
    if confirmation != "UNDO LABELS":
        raise GmailLabelExecutionError(
            "Confirmation phrase must exactly equal UNDO LABELS."
        )

    service = get_modify_service()

    results = []

    for item in execution_results:
        message_id = str(
            item.get(
                "message_id",
                "",
            )
        )

        label_ids = [
            str(
                value
            )
            for value in item.get(
                "applied_label_ids",
                []
            )
            if str(
                value
            )
        ]

        if not message_id or not label_ids:
            continue

        try:
            modified = (
                service.users()
                .messages()
                .modify(
                    userId="me",
                    id=message_id,
                    body={
                        "addLabelIds": [],
                        "removeLabelIds": (
                            label_ids
                        ),
                    },
                )
                .execute()
            )

            result = {
                "message_id": message_id,
                "removed_label_ids": label_ids,
                "remaining_label_ids": (
                    modified.get(
                        "labelIds",
                        []
                    )
                ),
                "success": True,
                "error": None,
                "executed_at": utc_now(),
            }

        except Exception as error:
            result = {
                "message_id": message_id,
                "removed_label_ids": [],
                "remaining_label_ids": [],
                "success": False,
                "error": str(
                    error
                ),
                "executed_at": utc_now(),
            }

        append_audit_record(
            {
                "event": "undo_labels",
                **result,
            }
        )

        results.append(
            result
        )

    return {
        "executed_at": utc_now(),
        "successful": sum(
            1
            for result in results
            if result[
                "success"
            ]
        ),
        "failed": sum(
            1
            for result in results
            if not result[
                "success"
            ]
        ),
        "results": results,
    }
