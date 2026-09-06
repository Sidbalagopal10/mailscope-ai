from __future__ import annotations

import pandas as pd
import plotly.express as px
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Combined Gmail Risk",
    page_icon="📧",
    layout="wide",
)

st.title("📧 Combined Gmail Risk")

st.caption(
    "Analyzes email content and URLs, then applies "
    "an AI Security risk label directly inside Gmail."
)


def api_get(
    endpoint: str,
    timeout: int = 30,
):
    response = requests.get(
        f"{API_BASE_URL}{endpoint}",
        timeout=timeout,
    )

    response.raise_for_status()

    return response.json()


def api_post(
    endpoint: str,
    timeout: int = 300,
):
    response = requests.post(
        f"{API_BASE_URL}{endpoint}",
        timeout=timeout,
    )

    response.raise_for_status()

    return response.json()


def show_request_error(
    error,
    fallback: str,
):
    try:
        detail = error.response.json().get(
            "detail",
            fallback,
        )
    except (ValueError, AttributeError):
        detail = str(error)

    st.error(detail)


st.sidebar.header(
    "Combined Gmail Scan"
)

scan_limit = st.sidebar.number_input(
    "Recent messages",
    min_value=1,
    max_value=25,
    value=5,
    step=1,
)

apply_labels = st.sidebar.checkbox(
    "Apply risk labels in Gmail",
    value=True,
)

st.sidebar.caption(
    "The application only manages labels beginning "
    "with “AI Security -”."
)


if st.sidebar.button(
    "Create Gmail Risk Labels",
    width="stretch",
):
    try:
        with st.spinner(
            "Preparing Gmail labels..."
        ):
            label_response = api_post(
                "/gmail-risk/setup-labels",
                timeout=120,
            )

        st.sidebar.success(
            "Gmail risk labels are ready."
        )

    except requests.ConnectionError:
        st.sidebar.error(
            "FastAPI is not running."
        )

    except requests.RequestException as error:
        st.sidebar.error(
            f"Unable to create labels: {error}"
        )


if st.sidebar.button(
    "Run Combined Scan",
    type="primary",
    width="stretch",
):
    with st.spinner(
        "Analyzing Gmail content and URLs..."
    ):
        try:
            scan_result = api_post(
                (
                    "/gmail-risk/scan"
                    f"?limit={int(scan_limit)}"
                    f"&apply_labels="
                    f"{str(apply_labels).lower()}"
                )
            )

            st.success(
                "Combined Gmail scan completed."
            )

            result_col1, result_col2 = (
                st.columns(2)
            )

            result_col1.metric(
                "Emails Scanned",
                scan_result[
                    "emails_scanned"
                ],
            )

            result_col2.metric(
                "Labels Applied",
                scan_result[
                    "labels_applied"
                ],
            )

            result_col3, result_col4 = (
                st.columns(2)
            )

            result_col3.metric(
                "Suspicious Emails",
                scan_result[
                    "suspicious_emails"
                ],
            )

            result_col4.metric(
                "Likely Phishing",
                scan_result[
                    "phishing_emails"
                ],
            )

            label_errors = scan_result.get(
                "label_errors",
                [],
            )

            if label_errors:
                st.warning(
                    f"{len(label_errors)} messages were "
                    "analyzed but could not be labeled."
                )

                with st.expander(
                    "View label errors"
                ):
                    st.json(
                        label_errors
                    )

        except requests.ConnectionError:
            st.error(
                "FastAPI is not running."
            )

        except requests.Timeout:
            st.error(
                "The Gmail scan timed out. "
                "Try scanning fewer messages."
            )

        except requests.HTTPError as error:
            show_request_error(
                error,
                "Combined Gmail scan failed.",
            )

        except requests.RequestException as error:
            st.error(
                f"Scan failed: {error}"
            )


try:
    summary = api_get(
        "/gmail-risk/summary"
    )

    history = api_get(
        "/gmail-risk/history?limit=300"
    )

except requests.ConnectionError:
    st.error(
        "FastAPI is not running."
    )

    st.stop()

except requests.RequestException as error:
    st.error(
        f"Unable to load results: {error}"
    )

    st.stop()


metric1, metric2, metric3, metric4 = (
    st.columns(4)
)

metric1.metric(
    "Emails Analyzed",
    summary["total_emails"],
)

metric2.metric(
    "Suspicious Emails",
    summary["suspicious_emails"],
)

metric3.metric(
    "Likely Phishing",
    summary["phishing_emails"],
)

metric4.metric(
    "Highest Score",
    f"{summary['highest_score']:.1f}/100",
)


metric5, metric6, metric7 = st.columns(3)

metric5.metric(
    "Average Score",
    f"{summary['average_score']:.1f}/100",
)

metric6.metric(
    "Links Inspected",
    summary["total_links"],
)

metric7.metric(
    "Suspicious URLs",
    summary["suspicious_urls"],
)


if not history:
    st.info(
        "No combined Gmail scans are available yet."
    )

    st.stop()


df = pd.DataFrame(
    history
)

df["updated_at"] = pd.to_datetime(
    df["updated_at"],
    errors="coerce",
)


st.divider()

filter1, filter2 = st.columns(2)

risk_filter = filter1.selectbox(
    "Risk level",
    [
        "All",
        "LOW",
        "GUARDED",
        "MODERATE",
        "HIGH",
        "CRITICAL",
    ],
)

search_text = filter2.text_input(
    "Search sender or subject"
)


filtered_df = df.copy()

if risk_filter != "All":
    filtered_df = filtered_df[
        filtered_df["risk_level"]
        == risk_filter
    ]

if search_text:
    value = search_text.lower()

    mask = (
        filtered_df["subject"]
        .fillna("")
        .astype(str)
        .str.lower()
        .str.contains(
            value,
            regex=False,
        )
        |
        filtered_df["sender"]
        .fillna("")
        .astype(str)
        .str.lower()
        .str.contains(
            value,
            regex=False,
        )
    )

    filtered_df = filtered_df[
        mask
    ]


st.subheader(
    "Combined Risk Results"
)

display_columns = [
    "subject",
    "sender",
    "content_score",
    "highest_url_score",
    "combined_score",
    "risk_level",
    "link_count",
    "suspicious_url_count",
    "updated_at",
]

st.dataframe(
    filtered_df[
        display_columns
    ],
    width="stretch",
    hide_index=True,
    column_config={
        "subject": "Subject",
        "sender": "Sender",
        "content_score": (
            st.column_config.NumberColumn(
                "Content Score",
                format="%.1f",
            )
        ),
        "highest_url_score": (
            st.column_config.NumberColumn(
                "Highest URL Score",
                format="%.1f",
            )
        ),
        "combined_score": (
            st.column_config.NumberColumn(
                "Combined Score",
                format="%.1f",
            )
        ),
        "risk_level": "Risk Level",
        "link_count": "Links",
        "suspicious_url_count": (
            "Suspicious URLs"
        ),
        "updated_at": (
            st.column_config.DatetimeColumn(
                "Scanned At",
                format="YYYY-MM-DD HH:mm:ss",
            )
        ),
    },
)


st.subheader(
    "Risk Distribution"
)

distribution = pd.DataFrame(
    [
        {
            "risk_level": key,
            "count": value,
        }
        for key, value
        in summary[
            "risk_distribution"
        ].items()
    ]
)

if not distribution.empty:
    figure = px.bar(
        distribution,
        x="risk_level",
        y="count",
        color="risk_level",
    )

    st.plotly_chart(
        figure,
        width="stretch",
    )


st.subheader(
    "Inspect an Email"
)

if not filtered_df.empty:
    email_options = {}

    for _, row in filtered_df.iterrows():
        label = (
            f"{row['risk_level']} | "
            f"{row['subject']} | "
            f"{row['sender']}"
        )

        email_options[
            label
        ] = row[
            "gmail_message_id"
        ]

    selected_label = st.selectbox(
        "Select a message",
        list(
            email_options.keys()
        ),
    )

    selected_id = email_options[
        selected_label
    ]

    selected_record = next(
        record
        for record in history
        if record[
            "gmail_message_id"
        ] == selected_id
    )

    analysis = selected_record.get(
        "analysis",
        {},
    )

    detail1, detail2, detail3 = (
        st.columns(3)
    )

    detail1.metric(
        "Combined Score",
        (
            f"{selected_record['combined_score']}"
            "/100"
        ),
    )

    detail2.metric(
        "Content Score",
        (
            f"{selected_record['content_score']}"
            "/100"
        ),
    )

    detail3.metric(
        "Highest URL Score",
        (
            f"{selected_record['highest_url_score']}"
            "/100"
        ),
    )

    st.write(
        "**Gmail label**"
    )

    st.code(
        "AI Security - "
        f"{selected_record['risk_level']}"
    )

    st.write(
        "**Recommendation**"
    )

    st.warning(
        selected_record.get(
            "recommendation",
            "Verify the email independently.",
        )
    )

    st.write(
        "**Reasons**"
    )

    reasons = selected_record.get(
        "reasons",
        [],
    )

    if reasons:
        for reason in reasons:
            st.write(
                f"- {reason}"
            )

    else:
        st.write(
            "No major reasons were recorded."
        )

    with st.expander(
        "View URL analysis results"
    ):
        url_results = analysis.get(
            "url_results",
            [],
        )

        if url_results:
            url_df = pd.DataFrame(
                [
                    {
                        "url": item.get(
                            "url"
                        ),
                        "score": item.get(
                            "final_score",
                            0,
                        ),
                        "risk_level": item.get(
                            "risk_level"
                        ),
                        "phishing": item.get(
                            "is_phishing",
                            False,
                        ),
                    }
                    for item in url_results
                ]
            )

            st.dataframe(
                url_df,
                width="stretch",
                hide_index=True,
            )

        else:
            st.write(
                "No URLs were found."
            )

    with st.expander(
        "View raw combined analysis"
    ):
        st.json(
            analysis
        )
