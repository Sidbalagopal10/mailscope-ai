import hashlib
from typing import Any, Dict, Optional

import requests
import streamlit as st


DEFAULT_API_URL = "http://127.0.0.1:8000"


def create_result_key(
    result: Dict[str, Any],
) -> str:
    url = str(result.get("url", ""))

    model_version = str(
        result.get(
            "components",
            {},
        )
        .get(
            "machine_learning",
            {},
        )
        .get(
            "model_version",
            "unknown",
        )
    )

    raw_key = f"{url}|{model_version}"

    return hashlib.sha256(
        raw_key.encode("utf-8")
    ).hexdigest()[:16]


def get_ml_component(
    result: Dict[str, Any],
) -> Dict[str, Any]:
    components = result.get(
        "components",
        {}
    )

    machine_learning = components.get(
        "machine_learning",
        {}
    )

    if not isinstance(
        machine_learning,
        dict,
    ):
        return {}

    return machine_learning


def get_predicted_label(
    result: Dict[str, Any],
) -> int:
    return (
        1
        if bool(
            result.get(
                "is_phishing",
                False,
            )
        )
        else 0
    )


def get_confirmed_label(
    predicted_label: int,
    is_prediction_correct: bool,
) -> int:
    if is_prediction_correct:
        return predicted_label

    return 1 - predicted_label


def build_feedback_payload(
    *,
    result: Dict[str, Any],
    is_prediction_correct: bool,
    notes: Optional[str] = None,
    source: str = "streamlit-dashboard",
) -> Dict[str, Any]:
    predicted_label = get_predicted_label(
        result
    )

    confirmed_label = get_confirmed_label(
        predicted_label=predicted_label,
        is_prediction_correct=(
            is_prediction_correct
        ),
    )

    ml_component = get_ml_component(
        result
    )

    probability = ml_component.get(
        "probability"
    )

    if probability is not None:
        probability = float(
            probability
        )

    final_score = result.get(
        "final_score"
    )

    if final_score is not None:
        final_score = float(
            final_score
        )

    payload = {
        "url": str(
            result.get(
                "url",
                "",
            )
        ).strip(),
        "predicted_label": (
            predicted_label
        ),
        "predicted_probability": (
            probability
        ),
        "final_score": final_score,
        "risk_level": result.get(
            "risk_level"
        ),
        "is_prediction_correct": (
            is_prediction_correct
        ),
        "confirmed_label": (
            confirmed_label
        ),
        "model_version": (
            ml_component.get(
                "model_version"
            )
        ),
        "model_type": (
            ml_component.get(
                "model_type"
            )
        ),
        "source": source,
        "notes": (
            notes.strip()
            if notes
            else None
        ),
        "analysis_snapshot": result,
    }

    return payload


def submit_feedback(
    *,
    payload: Dict[str, Any],
    api_url: str,
    timeout: int = 15,
) -> Dict[str, Any]:
    response = requests.post(
        f"{api_url.rstrip('/')}/feedback",
        json=payload,
        timeout=timeout,
    )

    if response.status_code not in {
        200,
        201,
    }:
        try:
            detail = response.json()
        except ValueError:
            detail = response.text

        raise RuntimeError(
            "Feedback submission failed "
            f"with status {response.status_code}: "
            f"{detail}"
        )

    return response.json()


def render_feedback_controls(
    *,
    result: Dict[str, Any],
    api_url: str = DEFAULT_API_URL,
    source: str = "streamlit-dashboard",
) -> None:
    result_key = create_result_key(
        result
    )

    submitted_key = (
        f"feedback_submitted_{result_key}"
    )

    record_key = (
        f"feedback_record_{result_key}"
    )

    notes_key = (
        f"feedback_notes_{result_key}"
    )

    st.divider()

    st.subheader(
        "Was this prediction correct?"
    )

    if st.session_state.get(
        submitted_key,
        False,
    ):
        record = st.session_state.get(
            record_key,
            {},
        )

        confirmed_classification = (
            record.get(
                "confirmed_classification",
                "unknown",
            )
        )

        feedback_id = record.get(
            "id",
            "unknown",
        )

        st.success(
            "Feedback saved. "
            f"Confirmed label: "
            f"{confirmed_classification}. "
            f"Feedback ID: {feedback_id}"
        )

        return

    predicted_label = get_predicted_label(
        result
    )

    predicted_classification = (
        "phishing"
        if predicted_label == 1
        else "benign"
    )

    st.caption(
        "Current prediction: "
        f"**{predicted_classification.title()}**. "
        "Feedback is used only as a "
        "human-verified label."
    )

    notes = st.text_area(
        "Optional feedback notes",
        placeholder=(
            "Example: This is an official "
            "company login page."
        ),
        key=notes_key,
        max_chars=2000,
    )

    correct_column, incorrect_column = (
        st.columns(2)
    )

    with correct_column:
        correct_clicked = st.button(
            "Correct",
            key=(
                f"feedback_correct_"
                f"{result_key}"
            ),
            type="primary",
            width="stretch",
        )

    with incorrect_column:
        incorrect_clicked = st.button(
            "Incorrect",
            key=(
                f"feedback_incorrect_"
                f"{result_key}"
            ),
            width="stretch",
        )

    if not (
        correct_clicked
        or incorrect_clicked
    ):
        return

    is_prediction_correct = bool(
        correct_clicked
    )

    payload = build_feedback_payload(
        result=result,
        is_prediction_correct=(
            is_prediction_correct
        ),
        notes=notes,
        source=source,
    )

    try:
        with st.spinner(
            "Saving verified feedback..."
        ):
            record = submit_feedback(
                payload=payload,
                api_url=api_url,
            )

        st.session_state[
            submitted_key
        ] = True

        st.session_state[
            record_key
        ] = record

        st.success(
            "Feedback saved successfully."
        )

        st.rerun()

    except requests.ConnectionError:
        st.error(
            "Could not connect to the "
            "FastAPI backend. Confirm that "
            "Uvicorn is running on "
            f"{api_url}."
        )

    except requests.Timeout:
        st.error(
            "The feedback request timed out."
        )

    except Exception as error:
        st.error(
            f"Unable to save feedback: {error}"
        )
