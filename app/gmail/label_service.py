from __future__ import annotations

from typing import Any


RISK_LEVELS = (
    "LOW",
    "GUARDED",
    "MODERATE",
    "HIGH",
    "CRITICAL",
)

LABEL_NAMES = {
    risk_level: f"AI Security - {risk_level}"
    for risk_level in RISK_LEVELS
}

LABEL_COLORS = {
    "LOW": {
        "backgroundColor": "#16a766",
        "textColor": "#ffffff",
    },
    "GUARDED": {
        "backgroundColor": "#f2c960",
        "textColor": "#000000",
    },
    "MODERATE": {
        "backgroundColor": "#ffad46",
        "textColor": "#000000",
    },
    "HIGH": {
        "backgroundColor": "#e66550",
        "textColor": "#ffffff",
    },
    "CRITICAL": {
        "backgroundColor": "#cc3a21",
        "textColor": "#ffffff",
    },
}


class GmailLabelError(Exception):
    pass


def normalize_risk_level(
    risk_level: str,
) -> str:
    normalized = str(
        risk_level or ""
    ).strip().upper()

    aliases = {
        "MEDIUM": "MODERATE",
    }

    normalized = aliases.get(
        normalized,
        normalized,
    )

    if normalized not in RISK_LEVELS:
        raise GmailLabelError(
            f"Unsupported risk level: {risk_level}"
        )

    return normalized


def list_labels(
    service,
) -> list[dict[str, Any]]:
    response = (
        service.users()
        .labels()
        .list(
            userId="me",
        )
        .execute()
    )

    return response.get(
        "labels",
        [],
    )


def get_label_map(
    service,
) -> dict[str, str]:
    return {
        label["name"]: label["id"]
        for label in list_labels(service)
        if label.get("name") and label.get("id")
    }


def create_risk_label(
    service,
    risk_level: str,
) -> dict[str, Any]:
    normalized = normalize_risk_level(
        risk_level
    )

    label_name = LABEL_NAMES[
        normalized
    ]

    body = {
        "name": label_name,
        "messageListVisibility": "show",
        "labelListVisibility": "labelShow",
        "color": LABEL_COLORS[
            normalized
        ],
    }

    return (
        service.users()
        .labels()
        .create(
            userId="me",
            body=body,
        )
        .execute()
    )


def ensure_risk_labels(
    service,
) -> dict[str, str]:
    existing = get_label_map(
        service
    )

    risk_label_ids = {}

    for risk_level in RISK_LEVELS:
        label_name = LABEL_NAMES[
            risk_level
        ]

        label_id = existing.get(
            label_name
        )

        if not label_id:
            created = create_risk_label(
                service,
                risk_level,
            )

            label_id = created["id"]

        risk_label_ids[
            risk_level
        ] = label_id

    return risk_label_ids


def apply_risk_label(
    *,
    service,
    gmail_message_id: str,
    risk_level: str,
) -> dict[str, Any]:
    normalized = normalize_risk_level(
        risk_level
    )

    label_ids = ensure_risk_labels(
        service
    )

    selected_label_id = label_ids[
        normalized
    ]

    labels_to_remove = [
        label_id
        for level, label_id
        in label_ids.items()
        if level != normalized
    ]

    modified_message = (
        service.users()
        .messages()
        .modify(
            userId="me",
            id=gmail_message_id,
            body={
                "addLabelIds": [
                    selected_label_id
                ],
                "removeLabelIds": (
                    labels_to_remove
                ),
            },
        )
        .execute()
    )

    return {
        "gmail_message_id": gmail_message_id,
        "risk_level": normalized,
        "label_name": LABEL_NAMES[
            normalized
        ],
        "label_id": selected_label_id,
        "message_label_ids": (
            modified_message.get(
                "labelIds",
                [],
            )
        ),
    }
