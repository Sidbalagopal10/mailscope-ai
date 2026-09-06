from __future__ import annotations

from typing import Any

import pandas as pd
import plotly.express as px
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Feedback Analytics",
    page_icon="📊",
    layout="wide",
)

st.title("📊 Feedback Analytics")

st.caption(
    "Review user feedback, detector accuracy, false positives, "
    "false negatives, and recent corrections."
)


def api_get(endpoint: str, timeout: int = 20) -> Any:
    response = requests.get(
        f"{API_BASE_URL}{endpoint}",
        timeout=timeout,
    )

    response.raise_for_status()
    return response.json()


def safe_number(
    value: Any,
    default: float = 0,
) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def extract_feedback_records(
    response_data: Any,
) -> list[dict[str, Any]]:
    if isinstance(response_data, list):
        return [
            record
            for record in response_data
            if isinstance(record, dict)
        ]

    if isinstance(response_data, dict):
        for key in (
            "feedback",
            "records",
            "items",
            "results",
            "data",
        ):
            records = response_data.get(key)

            if isinstance(records, list):
                return [
                    record
                    for record in records
                    if isinstance(record, dict)
                ]

    return []


def normalize_label(value: Any) -> str:
    normalized = str(value or "").strip().lower()

    phishing_labels = {
        "phishing",
        "malicious",
        "suspicious",
        "unsafe",
        "true",
        "1",
        "yes",
    }

    benign_labels = {
        "benign",
        "legitimate",
        "safe",
        "false",
        "0",
        "no",
    }

    if normalized in phishing_labels:
        return "Phishing"

    if normalized in benign_labels:
        return "Benign"

    return "Unknown"


def infer_prediction(record: dict[str, Any]) -> str:
    for key in (
        "predicted_label",
        "prediction",
        "classification",
        "predicted_class",
    ):
        if key in record:
            label = normalize_label(record.get(key))

            if label != "Unknown":
                return label

    for key in (
        "is_phishing",
        "predicted_is_phishing",
        "is_suspicious",
    ):
        if key in record:
            return (
                "Phishing"
                if bool(record.get(key))
                else "Benign"
            )

    return "Unknown"


def infer_actual_label(record: dict[str, Any]) -> str:
    for key in (
        "correct_label",
        "actual_label",
        "user_label",
        "corrected_label",
        "expected_label",
    ):
        if key in record:
            label = normalize_label(record.get(key))

            if label != "Unknown":
                return label

    feedback_value = str(
        record.get(
            "feedback",
            record.get(
                "feedback_type",
                record.get(
                    "verdict",
                    "",
                ),
            ),
        )
    ).strip().lower()

    predicted_label = infer_prediction(record)

    positive_feedback = {
        "correct",
        "accurate",
        "yes",
        "agree",
        "true",
        "thumbs_up",
    }

    negative_feedback = {
        "incorrect",
        "wrong",
        "no",
        "disagree",
        "false",
        "thumbs_down",
    }

    if feedback_value in positive_feedback:
        return predicted_label

    if feedback_value in negative_feedback:
        if predicted_label == "Phishing":
            return "Benign"

        if predicted_label == "Benign":
            return "Phishing"

    for key in (
        "is_correct",
        "correct",
    ):
        if key in record:
            is_correct = bool(record.get(key))

            if is_correct:
                return predicted_label

            if predicted_label == "Phishing":
                return "Benign"

            if predicted_label == "Benign":
                return "Phishing"

    return "Unknown"


def feedback_is_correct(record: dict[str, Any]) -> bool | None:
    predicted = infer_prediction(record)
    actual = infer_actual_label(record)

    if (
        predicted == "Unknown"
        or actual == "Unknown"
    ):
        return None

    return predicted == actual


try:
    summary_response = api_get(
        "/feedback/summary"
    )

    feedback_response = api_get(
        "/feedback"
    )

except requests.exceptions.ConnectionError:
    st.error(
        "FastAPI is not running. Start the backend first."
    )

    st.code(
        "python -m uvicorn app.main:app --reload"
    )

    st.stop()

except requests.exceptions.HTTPError as error:
    try:
        detail = error.response.json().get(
            "detail",
            str(error),
        )
    except ValueError:
        detail = str(error)

    st.error(
        f"Unable to load feedback data: {detail}"
    )

    st.stop()

except requests.exceptions.RequestException as error:
    st.error(
        f"Unable to connect to FastAPI: {error}"
    )

    st.stop()


summary = (
    summary_response
    if isinstance(summary_response, dict)
    else {}
)

records = extract_feedback_records(
    feedback_response
)

normalized_records = []

for record in records:
    normalized_record = dict(record)

    normalized_record["predicted_label_normalized"] = (
        infer_prediction(record)
    )

    normalized_record["actual_label_normalized"] = (
        infer_actual_label(record)
    )

    normalized_record["feedback_correct_normalized"] = (
        feedback_is_correct(record)
    )

    normalized_records.append(
        normalized_record
    )


total_feedback = int(
    safe_number(
        summary.get(
            "total_feedback",
            summary.get(
                "total",
                len(normalized_records),
            ),
        )
    )
)

correct_count = int(
    safe_number(
        summary.get(
            "correct_predictions",
            summary.get(
                "correct",
                sum(
                    item[
                        "feedback_correct_normalized"
                    ]
                    is True
                    for item in normalized_records
                ),
            ),
        )
    )
)

incorrect_count = int(
    safe_number(
        summary.get(
            "incorrect_predictions",
            summary.get(
                "incorrect",
                sum(
                    item[
                        "feedback_correct_normalized"
                    ]
                    is False
                    for item in normalized_records
                ),
            ),
        )
    )
)

accuracy = safe_number(
    summary.get(
        "accuracy",
        (
            correct_count / total_feedback
            if total_feedback
            else 0
        ),
    )
)

if accuracy <= 1:
    accuracy *= 100


true_positive = int(
    safe_number(
        summary.get(
            "true_positive",
            summary.get(
                "true_positives",
                sum(
                    item[
                        "predicted_label_normalized"
                    ]
                    == "Phishing"
                    and item[
                        "actual_label_normalized"
                    ]
                    == "Phishing"
                    for item in normalized_records
                ),
            ),
        )
    )
)

true_negative = int(
    safe_number(
        summary.get(
            "true_negative",
            summary.get(
                "true_negatives",
                sum(
                    item[
                        "predicted_label_normalized"
                    ]
                    == "Benign"
                    and item[
                        "actual_label_normalized"
                    ]
                    == "Benign"
                    for item in normalized_records
                ),
            ),
        )
    )
)

false_positive = int(
    safe_number(
        summary.get(
            "false_positive",
            summary.get(
                "false_positives",
                sum(
                    item[
                        "predicted_label_normalized"
                    ]
                    == "Phishing"
                    and item[
                        "actual_label_normalized"
                    ]
                    == "Benign"
                    for item in normalized_records
                ),
            ),
        )
    )
)

false_negative = int(
    safe_number(
        summary.get(
            "false_negative",
            summary.get(
                "false_negatives",
                sum(
                    item[
                        "predicted_label_normalized"
                    ]
                    == "Benign"
                    and item[
                        "actual_label_normalized"
                    ]
                    == "Phishing"
                    for item in normalized_records
                ),
            ),
        )
    )
)


metric_col1, metric_col2, metric_col3, metric_col4 = (
    st.columns(4)
)

metric_col1.metric(
    "Total Feedback",
    total_feedback,
)

metric_col2.metric(
    "Correct Predictions",
    correct_count,
)

metric_col3.metric(
    "Incorrect Predictions",
    incorrect_count,
)

metric_col4.metric(
    "Feedback Accuracy",
    f"{accuracy:.1f}%",
)


st.divider()

st.subheader("Confusion Matrix")

matrix_col1, matrix_col2, matrix_col3, matrix_col4 = (
    st.columns(4)
)

matrix_col1.metric(
    "True Positives",
    true_positive,
    help=(
        "Phishing URLs correctly classified "
        "as phishing."
    ),
)

matrix_col2.metric(
    "True Negatives",
    true_negative,
    help=(
        "Benign URLs correctly classified "
        "as benign."
    ),
)

matrix_col3.metric(
    "False Positives",
    false_positive,
    help=(
        "Benign URLs incorrectly classified "
        "as phishing."
    ),
)

matrix_col4.metric(
    "False Negatives",
    false_negative,
    help=(
        "Phishing URLs incorrectly classified "
        "as benign."
    ),
)


confusion_df = pd.DataFrame(
    {
        "Actual label": [
            "Phishing",
            "Phishing",
            "Benign",
            "Benign",
        ],
        "Predicted label": [
            "Phishing",
            "Benign",
            "Phishing",
            "Benign",
        ],
        "Count": [
            true_positive,
            false_negative,
            false_positive,
            true_negative,
        ],
    }
)

confusion_chart = px.bar(
    confusion_df,
    x="Actual label",
    y="Count",
    color="Predicted label",
    barmode="group",
    title="Prediction Outcomes",
)

st.plotly_chart(
    confusion_chart,
    width="stretch",
)


st.divider()

st.subheader("Feedback Distribution")

distribution_df = pd.DataFrame(
    {
        "Result": [
            "Correct",
            "Incorrect",
        ],
        "Count": [
            correct_count,
            incorrect_count,
        ],
    }
)

distribution_chart = px.pie(
    distribution_df,
    names="Result",
    values="Count",
    hole=0.45,
    title="Correct vs. Incorrect Predictions",
)

st.plotly_chart(
    distribution_chart,
    width="stretch",
)


st.divider()

st.subheader("Recent Feedback")

if not normalized_records:
    st.info(
        "No feedback has been submitted yet. "
        "Analyze a URL and use the Correct or Incorrect "
        "buttons to create feedback."
    )

else:
    feedback_df = pd.DataFrame(
        normalized_records
    )

    timestamp_column = None

    for candidate in (
        "created_at",
        "submitted_at",
        "timestamp",
        "feedback_at",
    ):
        if candidate in feedback_df.columns:
            timestamp_column = candidate
            break

    if timestamp_column:
        feedback_df[timestamp_column] = pd.to_datetime(
            feedback_df[timestamp_column],
            errors="coerce",
        )

        feedback_df = feedback_df.sort_values(
            timestamp_column,
            ascending=False,
        )

    preferred_columns = [
        "id",
        "url",
        "source",
        "predicted_label_normalized",
        "actual_label_normalized",
        "feedback_correct_normalized",
        "final_score",
        "risk_level",
        "created_at",
        "submitted_at",
        "timestamp",
    ]

    visible_columns = [
        column
        for column in preferred_columns
        if column in feedback_df.columns
    ]

    if not visible_columns:
        visible_columns = list(
            feedback_df.columns
        )

    st.dataframe(
        feedback_df[visible_columns],
        width="stretch",
        hide_index=True,
    )

    csv_data = feedback_df.to_csv(
        index=False
    ).encode("utf-8")

    st.download_button(
        "Export Feedback as CSV",
        data=csv_data,
        file_name="phishing_detector_feedback.csv",
        mime="text/csv",
        width="stretch",
    )


with st.expander(
    "View raw feedback summary"
):
    st.json(summary_response)
