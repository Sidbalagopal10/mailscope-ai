from __future__ import annotations

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = (
    "http://127.0.0.1:8000"
)


st.set_page_config(
    page_title="Continuous Learning",
    page_icon="��",
    layout="wide",
)

st.title(
    "🧬 Controlled Continuous Learning"
)

st.caption(
    "Retraining uses only human-confirmed "
    "feedback. A candidate model is promoted "
    "only if it passes safety checks."
)


def api_get(
    endpoint: str,
):
    response = requests.get(
        f"{API_BASE_URL}{endpoint}",
        timeout=30,
    )

    response.raise_for_status()
    return response.json()


def api_post(
    endpoint: str,
):
    response = requests.post(
        f"{API_BASE_URL}{endpoint}",
        timeout=7200,
    )

    response.raise_for_status()
    return response.json()


try:
    status = api_get(
        "/continuous-learning/status"
    )

except requests.RequestException as error:
    st.error(
        f"Unable to load status: {error}"
    )

    st.stop()


col1, col2, col3, col4 = (
    st.columns(4)
)

col1.metric(
    "Verified Feedback",
    status.get(
        "verified_feedback_count",
        0,
    ),
)

col2.metric(
    "Minimum Required",
    status.get(
        "minimum_feedback_required",
        25,
    ),
)

col3.metric(
    "Ready to Retrain",
    (
        "Yes"
        if status.get(
            "ready_for_retraining"
        )
        else "No"
    ),
)

col4.metric(
    "Last Promotion",
    status.get(
        "last_promoted_at"
    )
    or "None",
)


progress = min(
    status.get(
        "verified_feedback_count",
        0,
    )
    / max(
        status.get(
            "minimum_feedback_required",
            25,
        ),
        1,
    ),
    1.0,
)

st.progress(
    progress
)


button1, button2 = st.columns(
    2
)

with button1:
    safe_retrain = st.button(
        "Run Safe Retraining Check",
        type="primary",
        width="stretch",
    )

with button2:
    force_retrain = st.button(
        "Force Training for Testing",
        width="stretch",
    )


if safe_retrain or force_retrain:
    endpoint = (
        "/continuous-learning/retrain"
    )

    if force_retrain:
        endpoint += "?force=true"

    with st.spinner(
        "Training and evaluating candidate..."
    ):
        try:
            result = api_post(
                endpoint
            )

            if result.get(
                "status"
            ) == "promoted":
                st.success(
                    "Candidate model promoted."
                )

            elif result.get(
                "status"
            ) == "rejected":
                st.warning(
                    "Candidate model rejected."
                )

            else:
                st.info(
                    result.get(
                        "reason",
                        "Training skipped.",
                    )
                )

            st.json(
                result
            )

        except requests.RequestException as error:
            st.error(
                f"Retraining failed: {error}"
            )


report = status.get(
    "latest_report",
    {},
)

if report:
    st.divider()

    st.subheader(
        "Latest Evaluation"
    )

    current_metrics = report.get(
        "current_metrics",
        {},
    )

    candidate_metrics = report.get(
        "candidate_metrics",
        {},
    )

    rows = []

    for metric in [
        "accuracy",
        "precision",
        "recall",
        "f1_score",
        "false_positives",
        "false_negatives",
    ]:
        rows.append(
            {
                "metric": metric,
                "current_model": (
                    current_metrics.get(
                        metric
                    )
                ),
                "candidate_model": (
                    candidate_metrics.get(
                        metric
                    )
                ),
            }
        )

    st.dataframe(
        pd.DataFrame(
            rows
        ),
        width="stretch",
        hide_index=True,
    )

    st.write(
        "**Promotion checks**"
    )

    for name, passed in report.get(
        "promotion_checks",
        {},
    ).items():
        st.write(
            (
                "✅"
                if passed
                else "❌"
            ),
            name,
        )

    with st.expander(
        "View full report"
    ):
        st.json(
            report
        )


st.warning(
    "Routine retraining should use the safe "
    "button. Force mode is only for testing."
)
