from __future__ import annotations

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Email Content Analyzer",
    page_icon="🧠",
    layout="wide",
)

st.title("🧠 Email Content Analyzer")

st.caption(
    "Analyze email language for urgency, credential theft, "
    "financial pressure, impersonation, threats, and other "
    "social-engineering techniques."
)


with st.form(
    "email_content_form",
    clear_on_submit=False,
):
    sender = st.text_input(
        "Sender",
        placeholder=(
            "IT Support <security@example.com>"
        ),
    )

    subject = st.text_input(
        "Subject",
        placeholder=(
            "URGENT: Your account will be suspended"
        ),
    )

    body = st.text_area(
        "Email body",
        height=300,
        placeholder=(
            "Paste the email body here..."
        ),
    )

    submitted = st.form_submit_button(
        "Analyze Email Content",
        type="primary",
        width="stretch",
    )


if submitted:
    if not body.strip():
        st.warning(
            "Paste an email body before running the analysis."
        )

    else:
        with st.spinner(
            "Analyzing social-engineering indicators..."
        ):
            try:
                response = requests.post(
                    (
                        f"{API_BASE_URL}"
                        "/email-content/analyze"
                    ),
                    json={
                        "sender": sender.strip(),
                        "subject": subject.strip(),
                        "body": body.strip(),
                    },
                    timeout=30,
                )

                response.raise_for_status()

                st.session_state[
                    "email_content_result"
                ] = response.json()

            except requests.exceptions.ConnectionError:
                st.error(
                    "FastAPI is not running."
                )

            except requests.exceptions.Timeout:
                st.error(
                    "The analysis request timed out."
                )

            except requests.exceptions.HTTPError as error:
                try:
                    detail = error.response.json().get(
                        "detail",
                        str(error),
                    )
                except ValueError:
                    detail = str(error)

                st.error(
                    f"Email analysis failed: {detail}"
                )

            except requests.exceptions.RequestException as error:
                st.error(
                    f"Unable to analyze the email: {error}"
                )


result = st.session_state.get(
    "email_content_result"
)

if result:
    score = float(
        result.get(
            "content_score",
            0,
        )
    )

    risk_level = result.get(
        "risk_level",
        "UNKNOWN",
    )

    is_suspicious = bool(
        result.get(
            "is_suspicious",
            False,
        )
    )

    indicator_count = int(
        result.get(
            "indicator_count",
            0,
        )
    )

    if risk_level in {
        "HIGH",
        "CRITICAL",
    }:
        st.error(
            "Strong social-engineering indicators detected."
        )

    elif risk_level == "MODERATE":
        st.warning(
            "The email contains notable phishing language."
        )

    elif risk_level == "GUARDED":
        st.warning(
            "The email contains some suspicious language."
        )

    else:
        st.success(
            "No strong social-engineering indicators were found."
        )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Content Risk Score",
        f"{score:.1f}/100",
    )

    col2.metric(
        "Risk Level",
        risk_level,
    )

    col3.metric(
        "Suspicious",
        (
            "Yes"
            if is_suspicious
            else "No"
        ),
    )

    col4.metric(
        "Indicators",
        indicator_count,
    )

    st.subheader(
        "Recommendation"
    )

    st.info(
        result.get(
            "recommendation",
            "Verify the message independently.",
        )
    )

    indicators = result.get(
        "indicators",
        [],
    )

    st.subheader(
        "Detected Indicators"
    )

    if indicators:
        indicator_df = pd.DataFrame(
            indicators
        )

        st.dataframe(
            indicator_df,
            width="stretch",
            hide_index=True,
            column_config={
                "category": (
                    st.column_config.TextColumn(
                        "Category"
                    )
                ),
                "score": (
                    st.column_config.NumberColumn(
                        "Score Contribution",
                        format="%.1f",
                    )
                ),
                "match_count": (
                    st.column_config.NumberColumn(
                        "Matches"
                    )
                ),
                "explanation": (
                    st.column_config.TextColumn(
                        "Explanation"
                    )
                ),
            },
        )

        chart_df = indicator_df[
            [
                "category",
                "score",
            ]
        ].sort_values(
            "score",
            ascending=True,
        )

        st.bar_chart(
            chart_df,
            x="category",
            y="score",
            width="stretch",
        )

    else:
        st.write(
            "No content indicators were detected."
        )

    with st.expander(
        "View complete analysis result"
    ):
        st.json(
            result
        )


st.divider()

st.warning(
    "This analyzer evaluates message language only. "
    "A complete phishing decision should also consider "
    "sender identity, email headers, URLs, and attachments."
)
