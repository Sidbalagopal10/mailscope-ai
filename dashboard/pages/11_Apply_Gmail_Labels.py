from __future__ import annotations

import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Apply Gmail Labels",
    page_icon="✅",
    layout="wide",
)

st.title(
    "✅ Apply Approved Gmail Labels"
)

st.error(
    "This page can modify Gmail labels. It cannot delete, "
    "archive, mark spam, or remove messages from the inbox."
)


def api_get(
    path: str,
):
    response = requests.get(
        f"{API_BASE_URL}{path}",
        timeout=120,
    )

    response.raise_for_status()

    return response.json()


def api_post(
    path: str,
    payload: dict,
):
    response = requests.post(
        f"{API_BASE_URL}{path}",
        json=payload,
        timeout=180,
    )

    response.raise_for_status()

    return response.json()


try:
    plan = api_get(
        "/gmail-label-plan/latest"
    )

except requests.RequestException as error:
    st.error(
        f"Could not load the latest plan: {error}"
    )
    st.stop()


eligible = [
    item
    for item in plan.get(
        "plans",
        []
    )
    if item.get(
        "risk_level"
    )
    in {
        "moderate",
        "high",
        "critical",
    }
]


if not eligible:
    st.info(
        "The latest plan contains no moderate, high, "
        "or critical messages."
    )
    st.stop()


options = {
    (
        f"[{str(item.get('risk_level')).upper()}] "
        f"{item.get('subject') or '(No subject)'} "
        f"— {item.get('sender_address')}"
    ): item
    for item in eligible
}


selected_names = st.multiselect(
    "Select messages to label",
    options=list(
        options
    ),
)

for selected_name in selected_names:
    item = options[
        selected_name
    ]

    with st.expander(
        selected_name
    ):
        st.json(
            item
        )


st.subheader(
    "Required confirmation"
)

st.write(
    "Type exactly `APPLY LABELS` to authorize label-only changes."
)

confirmation = st.text_input(
    "Confirmation phrase",
)

apply_pressed = st.button(
    "Apply Selected Labels",
    type="primary",
    disabled=(
        not selected_names
        or confirmation
        != "APPLY LABELS"
    ),
    width="stretch",
)

if apply_pressed:
    try:
        result = api_post(
            "/gmail-label-execution/apply",
            {
                "message_ids": [
                    str(
                        options[name].get(
                            "message_id"
                        )
                    )
                    for name in selected_names
                ],
                "confirmation": (
                    confirmation
                ),
                "allow_low_risk": False,
            },
        )

        st.session_state[
            "latest_label_execution"
        ] = result

        if result.get(
            "failed",
            0,
        ):
            st.warning(
                "Some messages could not be labeled."
            )

        else:
            st.success(
                "Selected Gmail labels were applied."
            )

        st.json(
            result
        )

    except requests.HTTPError as error:
        try:
            detail = error.response.json().get(
                "detail"
            )

        except ValueError:
            detail = str(
                error
            )

        st.error(
            detail
        )

    except requests.RequestException as error:
        st.error(
            str(
                error
            )
        )


latest_execution = st.session_state.get(
    "latest_label_execution"
)

if latest_execution:
    st.divider()
    st.subheader(
        "Undo latest execution"
    )

    undo_confirmation = st.text_input(
        "Type UNDO LABELS",
        key="undo_confirmation",
    )

    if st.button(
        "Undo Applied Labels",
        disabled=(
            undo_confirmation
            != "UNDO LABELS"
        ),
        width="stretch",
    ):
        try:
            undo_result = api_post(
                "/gmail-label-execution/undo",
                {
                    "execution_results": (
                        latest_execution.get(
                            "results",
                            []
                        )
                    ),
                    "confirmation": (
                        undo_confirmation
                    ),
                },
            )

            st.success(
                "Undo request completed."
            )

            st.json(
                undo_result
            )

            st.session_state.pop(
                "latest_label_execution",
                None,
            )

        except requests.RequestException as error:
            st.error(
                str(
                    error
                )
            )
