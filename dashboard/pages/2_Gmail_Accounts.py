from __future__ import annotations

import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Gmail Accounts",
    page_icon="📨",
    layout="wide",
)

st.title("📨 Gmail Account Management")

st.caption(
    "Connect Gmail accounts, activate or pause monitoring, "
    "choose the primary account, or revoke access."
)


def load_accounts() -> list[dict]:
    response = requests.get(
        f"{API_BASE_URL}/gmail-accounts",
        timeout=30,
    )

    response.raise_for_status()

    return response.json().get(
        "accounts",
        [],
    )


def post_action(
    endpoint: str,
    timeout: int = 300,
):
    response = requests.post(
        f"{API_BASE_URL}{endpoint}",
        timeout=timeout,
    )

    response.raise_for_status()

    return response.json()


if st.button(
    "Connect Another Gmail Account",
    type="primary",
    width="stretch",
):
    with st.spinner(
        "Opening Google authorization..."
    ):
        try:
            connected = post_action(
                "/gmail-accounts/connect",
                timeout=300,
            )

            st.success(
                "Connected "
                f"{connected.get('email_address')}."
            )

            st.rerun()

        except requests.ConnectionError:
            st.error(
                "FastAPI is not running."
            )

        except requests.HTTPError as error:
            try:
                detail = error.response.json().get(
                    "detail",
                    str(error),
                )
            except ValueError:
                detail = str(error)

            st.error(detail)

        except requests.RequestException as error:
            st.error(
                f"Unable to connect Gmail: {error}"
            )


try:
    accounts = load_accounts()

except requests.ConnectionError:
    st.error(
        "FastAPI is not running."
    )

    st.stop()

except requests.RequestException as error:
    st.error(
        f"Unable to load Gmail accounts: {error}"
    )

    st.stop()


if not accounts:
    st.info(
        "No Gmail account is connected. "
        "Use Connect Another Gmail Account."
    )

    st.stop()


active_count = sum(
    1
    for account in accounts
    if account.get(
        "is_active"
    )
)

metric1, metric2 = st.columns(2)

metric1.metric(
    "Connected Accounts",
    len(accounts),
)

metric2.metric(
    "Active Accounts",
    active_count,
)


for account in accounts:
    email_address = account.get(
        "email_address",
        "Unknown account",
    )

    is_active = bool(
        account.get(
            "is_active"
        )
    )

    is_primary = bool(
        account.get(
            "is_primary"
        )
    )

    with st.container(
        border=True
    ):
        title = email_address

        if is_primary:
            title += " — Primary"

        st.subheader(
            title
        )

        status_col1, status_col2, status_col3 = (
            st.columns(3)
        )

        status_col1.metric(
            "Monitoring",
            (
                "Active"
                if is_active
                else "Paused"
            ),
        )

        status_col2.metric(
            "Connection",
            account.get(
                "connection_status",
                "unknown",
            ).title(),
        )

        status_col3.metric(
            "Last Scan",
            account.get(
                "last_scan_at"
            )
            or "Not scanned",
        )

        if account.get(
            "last_error"
        ):
            st.warning(
                account[
                    "last_error"
                ]
            )

        action1, action2, action3 = (
            st.columns(3)
        )

        if is_active:
            if action1.button(
                "Deactivate",
                key=(
                    f"deactivate_"
                    f"{account['id']}"
                ),
                width="stretch",
            ):
                post_action(
                    (
                        "/gmail-accounts/"
                        f"{account['id']}"
                        "/deactivate"
                    )
                )

                st.rerun()

        else:
            if action1.button(
                "Activate",
                key=(
                    f"activate_"
                    f"{account['id']}"
                ),
                type="primary",
                width="stretch",
            ):
                post_action(
                    (
                        "/gmail-accounts/"
                        f"{account['id']}"
                        "/activate"
                    )
                )

                st.rerun()

        if not is_primary:
            if action2.button(
                "Make Primary",
                key=(
                    f"primary_"
                    f"{account['id']}"
                ),
                disabled=not is_active,
                width="stretch",
            ):
                post_action(
                    (
                        "/gmail-accounts/"
                        f"{account['id']}"
                        "/primary"
                    )
                )

                st.rerun()

        confirm_disconnect = action3.checkbox(
            "Confirm disconnect",
            key=(
                f"confirm_disconnect_"
                f"{account['id']}"
            ),
        )

        if action3.button(
            "Disconnect",
            key=(
                f"disconnect_"
                f"{account['id']}"
            ),
            disabled=not confirm_disconnect,
            width="stretch",
        ):
            response = requests.delete(
                (
                    f"{API_BASE_URL}"
                    "/gmail-accounts/"
                    f"{account['id']}"
                ),
                timeout=60,
            )

            response.raise_for_status()

            st.success(
                f"Disconnected {email_address}."
            )

            st.rerun()


st.divider()

st.info(
    "Deactivate pauses scanning but keeps authorization. "
    "Disconnect revokes Google authorization and removes "
    "the locally stored token."
)
