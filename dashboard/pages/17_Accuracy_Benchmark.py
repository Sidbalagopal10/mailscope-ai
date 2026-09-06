from __future__ import annotations

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Accuracy Benchmark",
    page_icon="📊",
    layout="wide",
)

st.title(
    "📊 Email Security Accuracy Benchmark"
)

st.warning(
    "This is a deterministic regression benchmark. "
    "It does not prove real-world production accuracy."
)


def api_post(
    path: str,
):
    response = requests.post(
        f"{API_BASE_URL}{path}",
        timeout=600,
    )

    response.raise_for_status()

    return response.json()


false_positive_limit = st.slider(
    "Maximum acceptable false-positive rate",
    min_value=0.0,
    max_value=0.50,
    value=0.10,
    step=0.01,
)

if st.button(
    "Run Accuracy Benchmark",
    type="primary",
    width="stretch",
):
    try:
        with st.spinner(
            "Running deterministic email-security cases..."
        ):
            report = api_post(
                (
                    "/evaluation/run"
                    f"?maximum_false_positive_rate="
                    f"{false_positive_limit}"
                )
            )

        current = report.get(
            "current_threshold_metrics",
            {},
        )

        recommended = report.get(
            "recommended_metrics",
            {},
        )

        metric1, metric2, metric3, metric4 = st.columns(4)

        metric1.metric(
            "Cases",
            report.get(
                "case_count",
                0,
            ),
        )

        metric2.metric(
            "Current Balanced Accuracy",
            current.get(
                "balanced_accuracy"
            ),
        )

        metric3.metric(
            "Recommended Threshold",
            report.get(
                "recommended_threshold"
            ),
        )

        metric4.metric(
            "Recommended FPR",
            recommended.get(
                "false_positive_rate"
            ),
        )

        st.subheader(
            "Current Threshold — 60"
        )

        st.json(
            current
        )

        st.subheader(
            "Recommended Threshold"
        )

        st.json(
            recommended
        )

        threshold_frame = pd.DataFrame(
            report.get(
                "threshold_metrics",
                [],
            )
        )

        if not threshold_frame.empty:
            st.dataframe(
                threshold_frame,
                width="stretch",
                hide_index=True,
            )

            st.line_chart(
                threshold_frame.set_index(
                    "threshold"
                )[
                    [
                        "balanced_accuracy",
                        "precision",
                        "recall",
                        "f1",
                        "false_positive_rate",
                    ]
                ]
            )

        st.subheader(
            "Performance by Category"
        )

        st.dataframe(
            pd.DataFrame(
                report.get(
                    "category_summary",
                    [],
                )
            ),
            width="stretch",
            hide_index=True,
        )

        st.subheader(
            "Individual Cases"
        )

        case_frame = pd.DataFrame(
            report.get(
                "results",
                [],
            )
        )

        if not case_frame.empty:
            case_frame[
                "recommended_prediction"
            ] = (
                case_frame[
                    "score"
                ]
                >= float(
                    report.get(
                        "recommended_threshold",
                        60,
                    )
                )
            ).astype(
                int
            )

            case_frame[
                "correct"
            ] = (
                case_frame[
                    "recommended_prediction"
                ]
                == case_frame[
                    "true_label"
                ]
            )

            st.dataframe(
                case_frame[
                    [
                        "id",
                        "category",
                        "true_label",
                        "score",
                        "risk_level",
                        "recommended_prediction",
                        "correct",
                    ]
                ],
                width="stretch",
                hide_index=True,
            )

        st.code(
            "automatic_threshold_change: false\n"
            "manual_review_required: true\n"
            "real_world_accuracy_claim: false"
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
