from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

CREDENTIALS_FILE = PROJECT_ROOT / "credentials.json"

ACCOUNT_DIRECTORY = PROJECT_ROOT / "data/gmail_accounts"

DATABASE_PATH = ACCOUNT_DIRECTORY / "accounts.db"

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
]


class GmailAccountError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def get_connection() -> sqlite3.Connection:
    ACCOUNT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=30,
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA journal_mode=WAL"
    )

    return connection


def initialize_database() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS gmail_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_key TEXT NOT NULL UNIQUE,
                email_address TEXT NOT NULL UNIQUE,
                google_user_id TEXT,
                token_path TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                is_primary INTEGER NOT NULL DEFAULT 0,
                connection_status TEXT NOT NULL DEFAULT 'connected',
                connected_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_scan_at TEXT,
                last_error TEXT
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_gmail_accounts_active
            ON gmail_accounts(is_active)
            """
        )

        connection.commit()


def sanitize_email(
    email_address: str,
) -> str:
    cleaned = re.sub(
        r"[^a-zA-Z0-9._-]+",
        "_",
        email_address.strip().lower(),
    )

    return cleaned or "gmail_account"


def create_account_key(
    email_address: str,
) -> str:
    digest = hashlib.sha256(
        email_address.strip().lower().encode(
            "utf-8"
        )
    ).hexdigest()[:12]

    return (
        f"{sanitize_email(email_address)}"
        f"_{digest}"
    )


def token_path_for_account(
    email_address: str,
) -> Path:
    account_key = create_account_key(
        email_address
    )

    return (
        ACCOUNT_DIRECTORY
        / f"{account_key}.token.json"
    )


def credentials_from_path(
    token_path: Path,
) -> Credentials:
    if not token_path.exists():
        raise GmailAccountError(
            f"Token file was not found: {token_path}"
        )

    credentials = (
        Credentials.from_authorized_user_file(
            str(token_path),
            SCOPES,
        )
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
        raise GmailAccountError(
            "The Gmail authorization is no longer valid."
        )

    return credentials


def build_gmail_service(
    credentials: Credentials,
):
    return build(
        "gmail",
        "v1",
        credentials=credentials,
        cache_discovery=False,
    )


def get_profile(
    service,
) -> dict[str, Any]:
    return (
        service.users()
        .getProfile(
            userId="me",
        )
        .execute()
    )


def connect_new_account() -> dict[str, Any]:
    initialize_database()

    if not CREDENTIALS_FILE.exists():
        raise GmailAccountError(
            "credentials.json was not found in the project root."
        )

    flow = InstalledAppFlow.from_client_secrets_file(
        str(CREDENTIALS_FILE),
        SCOPES,
    )

    credentials = flow.run_local_server(
        port=0,
        open_browser=True,
        access_type="offline",
        prompt="select_account consent",
    )

    service = build_gmail_service(
        credentials
    )

    profile = get_profile(
        service
    )

    email_address = str(
        profile.get(
            "emailAddress",
            "",
        )
    ).strip().lower()

    google_user_id = str(
        profile.get(
            "emailAddress",
            "",
        )
    ).strip().lower()

    if not email_address:
        raise GmailAccountError(
            "Google did not return the Gmail address."
        )

    token_path = token_path_for_account(
        email_address
    )

    token_path.write_text(
        credentials.to_json(),
        encoding="utf-8",
    )

    token_path.chmod(
        0o600
    )

    timestamp = utc_now()

    with get_connection() as connection:
        existing_count = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM gmail_accounts
                """
            ).fetchone()[0]
        )

        make_primary = (
            1
            if existing_count == 0
            else 0
        )

        connection.execute(
            """
            INSERT INTO gmail_accounts (
                account_key,
                email_address,
                google_user_id,
                token_path,
                is_active,
                is_primary,
                connection_status,
                connected_at,
                updated_at,
                last_error
            )
            VALUES (?, ?, ?, ?, 1, ?, 'connected', ?, ?, NULL)
            ON CONFLICT(email_address)
            DO UPDATE SET
                google_user_id = excluded.google_user_id,
                token_path = excluded.token_path,
                is_active = 1,
                connection_status = 'connected',
                updated_at = excluded.updated_at,
                last_error = NULL
            """,
            (
                create_account_key(
                    email_address
                ),
                email_address,
                google_user_id,
                str(token_path),
                make_primary,
                timestamp,
                timestamp,
            ),
        )

        connection.commit()

    return get_account_by_email(
        email_address
    )


def row_to_dict(
    row: sqlite3.Row,
) -> dict[str, Any]:
    record = dict(row)

    record["is_active"] = bool(
        record["is_active"]
    )

    record["is_primary"] = bool(
        record["is_primary"]
    )

    record.pop(
        "token_path",
        None,
    )

    return record


def list_accounts() -> list[dict[str, Any]]:
    initialize_database()

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM gmail_accounts
            ORDER BY is_primary DESC, connected_at ASC
            """
        ).fetchall()

    return [
        row_to_dict(row)
        for row in rows
    ]


def get_account_by_id(
    account_id: int,
) -> dict[str, Any] | None:
    initialize_database()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM gmail_accounts
            WHERE id = ?
            """,
            (account_id,),
        ).fetchone()

    if row is None:
        return None

    return row_to_dict(row)


def get_account_by_email(
    email_address: str,
) -> dict[str, Any] | None:
    initialize_database()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM gmail_accounts
            WHERE email_address = ?
            """,
            (
                email_address.strip().lower(),
            ),
        ).fetchone()

    if row is None:
        return None

    return row_to_dict(row)


def get_account_internal(
    account_id: int,
) -> sqlite3.Row:
    initialize_database()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM gmail_accounts
            WHERE id = ?
            """,
            (account_id,),
        ).fetchone()

    if row is None:
        raise GmailAccountError(
            "Gmail account was not found."
        )

    return row


def get_primary_or_active_account_internal() -> sqlite3.Row:
    initialize_database()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM gmail_accounts
            WHERE is_active = 1
            ORDER BY is_primary DESC, connected_at ASC
            LIMIT 1
            """
        ).fetchone()

    if row is None:
        raise GmailAccountError(
            "No active Gmail account is connected."
        )

    return row


def get_service_for_account(
    account_id: int,
):
    row = get_account_internal(
        account_id
    )

    if not bool(
        row["is_active"]
    ):
        raise GmailAccountError(
            "This Gmail account is currently deactivated."
        )

    token_path = Path(
        row["token_path"]
    )

    try:
        credentials = credentials_from_path(
            token_path
        )

        return build_gmail_service(
            credentials
        )

    except Exception as error:
        mark_account_error(
            account_id,
            str(error),
        )

        raise


def get_service_for_active_account():
    row = (
        get_primary_or_active_account_internal()
    )

    return get_service_for_account(
        int(row["id"])
    )


def set_account_active(
    account_id: int,
    is_active: bool,
) -> dict[str, Any]:
    get_account_internal(
        account_id
    )

    with get_connection() as connection:
        connection.execute(
            """
            UPDATE gmail_accounts
            SET
                is_active = ?,
                updated_at = ?,
                connection_status = CASE
                    WHEN ? = 1
                    THEN 'connected'
                    ELSE 'paused'
                END
            WHERE id = ?
            """,
            (
                int(is_active),
                utc_now(),
                int(is_active),
                account_id,
            ),
        )

        connection.commit()

    account = get_account_by_id(
        account_id
    )

    if account is None:
        raise GmailAccountError(
            "Account state could not be retrieved."
        )

    return account


def set_primary_account(
    account_id: int,
) -> dict[str, Any]:
    row = get_account_internal(
        account_id
    )

    if not bool(
        row["is_active"]
    ):
        raise GmailAccountError(
            "Activate the account before making it primary."
        )

    with get_connection() as connection:
        connection.execute(
            """
            UPDATE gmail_accounts
            SET is_primary = 0
            """
        )

        connection.execute(
            """
            UPDATE gmail_accounts
            SET
                is_primary = 1,
                updated_at = ?
            WHERE id = ?
            """,
            (
                utc_now(),
                account_id,
            ),
        )

        connection.commit()

    account = get_account_by_id(
        account_id
    )

    if account is None:
        raise GmailAccountError(
            "Primary account could not be retrieved."
        )

    return account


def revoke_credentials(
    credentials: Credentials,
) -> None:
    token = (
        credentials.refresh_token
        or credentials.token
    )

    if not token:
        return

    response = requests.post(
        "https://oauth2.googleapis.com/revoke",
        params={
            "token": token,
        },
        headers={
            "content-type": (
                "application/x-www-form-urlencoded"
            ),
        },
        timeout=30,
    )

    if response.status_code not in {
        200,
        400,
    }:
        response.raise_for_status()


def disconnect_account(
    account_id: int,
) -> dict[str, Any]:
    row = get_account_internal(
        account_id
    )

    token_path = Path(
        row["token_path"]
    )

    revoked = False
    revoke_error = None

    if token_path.exists():
        try:
            credentials = (
                Credentials.from_authorized_user_file(
                    str(token_path),
                    SCOPES,
                )
            )

            revoke_credentials(
                credentials
            )

            revoked = True

        except Exception as error:
            revoke_error = str(
                error
            )

        token_path.unlink(
            missing_ok=True
        )

    was_primary = bool(
        row["is_primary"]
    )

    with get_connection() as connection:
        connection.execute(
            """
            DELETE FROM gmail_accounts
            WHERE id = ?
            """,
            (account_id,),
        )

        if was_primary:
            next_account = connection.execute(
                """
                SELECT id
                FROM gmail_accounts
                WHERE is_active = 1
                ORDER BY connected_at ASC
                LIMIT 1
                """
            ).fetchone()

            if next_account:
                connection.execute(
                    """
                    UPDATE gmail_accounts
                    SET is_primary = 1
                    WHERE id = ?
                    """,
                    (
                        int(
                            next_account["id"]
                        ),
                    ),
                )

        connection.commit()

    return {
        "status": "disconnected",
        "email_address": row[
            "email_address"
        ],
        "authorization_revoked": revoked,
        "revocation_error": revoke_error,
    }


def mark_scan_completed(
    account_id: int,
) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE gmail_accounts
            SET
                last_scan_at = ?,
                updated_at = ?,
                last_error = NULL,
                connection_status = 'connected'
            WHERE id = ?
            """,
            (
                utc_now(),
                utc_now(),
                account_id,
            ),
        )

        connection.commit()


def mark_account_error(
    account_id: int,
    error_message: str,
) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE gmail_accounts
            SET
                last_error = ?,
                updated_at = ?,
                connection_status = 'error'
            WHERE id = ?
            """,
            (
                error_message,
                utc_now(),
                account_id,
            ),
        )

        connection.commit()


def get_active_account_rows() -> list[sqlite3.Row]:
    initialize_database()

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM gmail_accounts
            WHERE is_active = 1
            ORDER BY is_primary DESC, connected_at ASC
            """
        ).fetchall()

    return rows
