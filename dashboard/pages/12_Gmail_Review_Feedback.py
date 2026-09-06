from __future__ import annotations

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Gmail Review Feedback",
    page_icon="🧠",
    layout="wide",
)

st.title(
    "🧠 Gmail Human Review and Feedback"
)

st.info(
    "Only explicit human reviews become eligible training data. "
    "Unreviewed messages and 'Unsure' reviews are excluded."
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
        timeout=120,
    )

    response.raise_for_status()

    return response.json()


try:
    summary = api_get(
        "/gmail-feedback/summary"
    )

    candidates = api_get(
        "/gmail-feedback/candidates"
    ).get(
        "candidates",
        [],
    )

except requests.RequestException as error:
    st.error(
        f"Unable to load feedback data: {error}"
    )

    st.stop()


metric1, metric2, metric3, metric4 = st.columns(4)

metric1.metric(
    "Reviewed",
    summary.get(
        "total_reviews",
        0,
    ),
)

metric2.metric(
    "Training Eligible",
    summary.get(
        "training_eligible",
        0,
    ),
)

metric3.metric(
    "False Positives",
    summary.get(
        "false_positive",
        0,
    ),
)

metric4.metric(
    "Reviewed Accuracy",
    (
        f"{summary.get('reviewed_accuracy_percentage')}%"
        if summary.get(
            "reviewed_accuracy_percentage"
        )
        is not None
        else "N/A"
    ),
)


review_tab, history_tab = st.tabs(
    [
        "Review Latest Messages",
        "Review History",
    ]
)


with review_tab:
    if not candidates:
        st.warning(
            "No label-plan candidates exist. Run Gmail "
            "Observation Mode and the dry-run planner first."
        )

    else:
        option_map = {
            (
                f"[{str(item.get('risk_level', 'low')).upper()}] "
                f"{item.get('subject') or '(No subject)'} "
                f"— {item.get('sender_address')}"
            ): item
            for item in candidates
        }

        selected_name = st.selectbox(
            "Message to review",
            options=list(
                option_map
            ),
        )

        selected = option_map[
            selected_name
        ]

        st.json(
            selected
        )

        verdict_label = st.radio(
            "Your verdict",
            options=[
                "Correct phishing",
                "False positive",
                "False negative",
                "Correct legitimate",
                "Unsure",
            ],
        )

        verdict_map = {
            "Correct phishing": (
                "correct_phishing"
            ),
            "False positive": (
                "false_positive"
            ),
            "False negative": (
                "false_negative"
            ),
            "Correct legitimate": (
                "correct_legitimate"
            ),
            "Unsure": "unsure",
        }

        notes = st.text_area(
            "Reviewer notes",
            placeholder=(
                "Explain why the detector was correct or incorrect."
            ),
        )

        if st.button(
            "Save Human Review",
            type="primary",
            width="stretch",
        ):
            try:
                result = api_post(
                    "/gmail-feedback/review",
                    {
                        "message_id": selected.get(
                            "message_id"
                        ),
                        "review_verdict": (
                            verdict_map[
                                verdict_label
                            ]
                        ),
                        "reviewer_notes": (
                            notes.strip()
                            or None
                        ),
                    },
                )

                if result.get(
                    "include_in_training"
                ):
                    st.success(
                        "Review saved and marked as eligible "
                        "for the reviewed training dataset."
                    )

                else:
                    st.info(
                        "Review saved but excluded from training."
                    )

                st.json(
                    result
                )

            except requests.HTTPError as error:
                try:
                    detail = (
                        error.response.json().get(
                            "detail"
                        )
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


with history_tab:
    try:
        reviews = api_get(
            "/gmail-feedback/reviews?limit=1000"
        ).get(
            "reviews",
            [],
        )

    except requests.RequestException as error:
        st.error(
            str(
                error
            )
        )

        reviews = []

    if reviews:
        frame = pd.DataFrame(
            reviews
        )

        visible_columns = [
            "reviewed_at",
            "subject",
            "sender_address",
            "predicted_score",
            "predicted_risk_level",
            "review_verdict",
            "reviewer_label",
            "include_in_training",
            "reviewer_notes",
        ]

        available_columns = [
            column
            for column in visible_columns
            if column in frame.columns
        ]

        st.dataframe(
            frame[
                available_columns
            ],
            width="stretch",
            hide_index=True,
        )

    else:
        st.info(
            "No human reviews have been submitted yet."
        )
