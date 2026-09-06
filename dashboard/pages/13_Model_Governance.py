from __future__ import annotations

import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Model Governance",
    page_icon="🛡️",
    layout="wide",
)

st.title(
    "��️ Human-Reviewed Model Governance"
)

st.warning(
    "This page can train a staged calibration candidate, "
    "but it cannot automatically replace the active detector."
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
    payload: dict | None = None,
):
    response = requests.post(
        f"{API_BASE_URL}{path}",
        json=payload,
        timeout=300,
    )

    response.raise_for_status()

    return response.json()


try:
    status = api_get(
        "/model-governance/status"
    )

except requests.RequestException as error:
    st.error(
        f"Could not load model-governance status: {error}"
    )

    st.stop()


dataset = status.get(
    "dataset",
    {},
)

metric1, metric2, metric3, metric4 = st.columns(4)

metric1.metric(
    "Reviewed Examples",
    dataset.get(
        "total_examples",
        0,
    ),
)

metric2.metric(
    "Phishing",
    dataset.get(
        "phishing_examples",
        0,
    ),
)

metric3.metric(
    "Legitimate",
    dataset.get(
        "legitimate_examples",
        0,
    ),
)

metric4.metric(
    "Training Gate",
    (
        "OPEN"
        if dataset.get(
            "training_gate_open"
        )
        else "CLOSED"
    ),
)


if not dataset.get(
    "training_gate_open"
):
    st.info(
        "The gate requires at least 40 reviewed messages, "
        "including at least 15 phishing and 15 legitimate examples."
    )


if st.button(
    "Train and Evaluate Staged Candidate",
    type="primary",
    disabled=(
        not dataset.get(
            "training_gate_open"
        )
    ),
    width="stretch",
):
    try:
        with st.spinner(
            "Training on the training split and evaluating "
            "against unseen holdout examples..."
        ):
            report = api_post(
                "/model-governance/train-candidate"
            )

        promotion = report.get(
            "promotion_gate",
            {},
        )

        if promotion.get(
            "eligible_for_manual_promotion"
        ):
            st.success(
                "The candidate passed the evaluation gate. "
                "It remains staged and has not changed the active model."
            )

        else:
            st.warning(
                "The candidate did not pass every promotion criterion. "
                "The active model remains unchanged."
            )

        st.json(
            report
        )

    except requests.HTTPError as error:
        try:
            detail = error.response.json().get(
                "detail",
                str(
                    error
                ),
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


latest_report = status.get(
    "latest_report"
)

if latest_report:
    st.divider()
    st.subheader(
        "Latest Evaluation"
    )

    baseline = latest_report.get(
        "baseline",
        {},
    ).get(
        "metrics",
        {},
    )

    candidate = latest_report.get(
        "candidate",
        {},
    ).get(
        "metrics",
        {},
    )

    column1, column2, column3, column4 = st.columns(4)

    column1.metric(
        "Baseline Balanced Accuracy",
        baseline.get(
            "balanced_accuracy"
        ),
    )

    column2.metric(
        "Candidate Balanced Accuracy",
        candidate.get(
            "balanced_accuracy"
        ),
    )

    column3.metric(
        "Baseline False Positive Rate",
        baseline.get(
            "false_positive_rate"
        ),
    )

    column4.metric(
        "Candidate False Positive Rate",
        candidate.get(
            "false_positive_rate"
        ),
    )

    st.json(
        latest_report
    )


st.divider()
st.subheader(
    "Staged Candidate Test"
)

score = st.slider(
    "Current detector score",
    min_value=0.0,
    max_value=100.0,
    value=50.0,
)

risk_level = st.selectbox(
    "Current risk level",
    [
        "low",
        "moderate",
        "high",
        "critical",
    ],
)

classification = st.selectbox(
    "Current classification",
    [
        "likely_legitimate",
        "needs_review",
        "high_risk",
        "likely_phishing",
    ],
)

if st.button(
    "Test Staged Candidate",
    disabled=(
        not status.get(
            "candidate_exists"
        )
    ),
    width="stretch",
):
    try:
        result = api_post(
            "/model-governance/candidate-prediction",
            {
                "predicted_score": score,
                "predicted_risk_level": (
                    risk_level
                ),
                "predicted_classification": (
                    classification
                ),
            },
        )

        st.json(
            result
        )

    except requests.RequestException as error:
        st.error(
            str(
                error
            )
        )


st.code(
    "automatic_model_replacement: false\n"
    "candidate_staging_only: true\n"
    "active_model_changed: false"
)
