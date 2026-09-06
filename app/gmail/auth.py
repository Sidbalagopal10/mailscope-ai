from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

CREDENTIALS_FILE = PROJECT_ROOT / "credentials.json"
TOKEN_FILE = PROJECT_ROOT / "token.json"

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
]


def get_gmail_credentials() -> Credentials:
    credentials = None

    if TOKEN_FILE.exists():
        try:
            credentials = Credentials.from_authorized_user_file(
                str(TOKEN_FILE),
                SCOPES,
            )
        except ValueError:
            credentials = None

    if (
        credentials
        and credentials.expired
        and credentials.refresh_token
    ):
        credentials.refresh(Request())

    elif not credentials or not credentials.valid:
        if not CREDENTIALS_FILE.exists():
            raise FileNotFoundError(
                f"OAuth credentials not found: {CREDENTIALS_FILE}"
            )

        flow = InstalledAppFlow.from_client_secrets_file(
            str(CREDENTIALS_FILE),
            SCOPES,
        )

        credentials = flow.run_local_server(
            port=0,
            open_browser=True,
        )

    TOKEN_FILE.write_text(
        credentials.to_json(),
        encoding="utf-8",
    )

    return credentials
