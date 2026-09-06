from __future__ import annotations

from app.gmail.account_manager import (
    GmailAccountError,
    get_service_for_active_account,
    get_service_for_account,
)


def get_gmail_service(
    account_id: int | None = None,
):
    """
    Return a Gmail API service.

    Existing project code can continue calling this function
    without arguments. It will use the primary active account.
    """
    if account_id is not None:
        return get_service_for_account(
            account_id
        )

    return get_service_for_active_account()
