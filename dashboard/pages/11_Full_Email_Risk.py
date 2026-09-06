from __future__ import annotations

import pandas as pd
import plotly.express as px
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Full Email Risk",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Full Email Risk Analysis")

st.caption(
    "Combines email language, URL machine learning, and "
    "SPF/DKIM/DMARC authentication into one score."
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


scan_col1, scan_col2 = st.columns(
    2
)

with scan_col1:
    scan_limit = st.number_input(
        "Recent Gmail messages",
        min_value=1,
        max_value=25,
        value=5,
        step=1,
    )

with scan_col2:
    apply_labels = st.checkbox(
        "Apply AI Security labels in Gmail",
        value=True,
    )


if st.button(
    "Run Full Email Scan",
    type="primary",
    width="stretch",
):
    with st.spinner(
        "Analyzing content, URLs, and email headers..."
    ):
        try:
            response = api_post(
                (
                    "/gmail-risk/scan"
                    f"?limit={int(scan_limit)}"
                    f"&apply_labels="
                    f"{str(apply_labels).lower()}"
                )
            )

            st.success(
                "Full Gmail risk scan completed."
            )

            result1, result2, result3, result4 = (
                st.columns(4)
            )

            result1.metric(
                "Emails Scanned",
                response.get(
                    "emails_scanned",
                    0,
                ),
            )

            result2.metric(
                "Suspicious",
                response.get(
                    "suspicious_emails",
                    0,
                ),
            )

            result3.metric(
                "Likely Phishing",
                response.get(
                    "phishing_emails",
                    0,
                ),
            )

            result4.metric(
                "Labels Applied",
                response.get(
                    "labels_applied",
                    0,
                ),
            )

        except requests.ConnectionError:
            st.error(
                "FastAPI is not running."
            )

        except requests.Timeout:
            st.error(
                "The full Gmail scan timed out. "
                "Try scanning fewer messages."
            )

        except requests.HTTPError as error:
            try:
                detail = (
                    error.response.json()
                    .get(
                        "detail",
                        str(error),
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
                f"Full Gmail scan failed: {error}"
            )


try:
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
        f"Unable to load Gmail history: {error}"
    )

    st.stop()


if not history:
    st.info(
        "No full Gmail scan results are available yet."
    )

    st.stop()


rows = []

for record in history:
    analysis = record.get(
        "analysis",
        {},
    )

    header_analysis = analysis.get(
        "header_analysis",
        {},
    )

    rows.append(
        {
            "gmail_message_id": (
                record.get(
                    "gmail_message_id"
                )
            ),
            "subject": record.get(
                "subject"
            ),
            "sender": record.get(
                "sender"
            ),
            "content_score": record.get(
                "content_score",
                0,
            ),
            "highest_url_score": (
                record.get(
                    "highest_url_score",
                    0,
                )
            ),
            "header_score": analysis.get(
                "header_score",
                0,
            ),
            "combined_score": record.get(
                "combined_score",
                0,
            ),
            "risk_level": record.get(
                "risk_level"
            ),
            "spf": header_analysis.get(
                "spf",
                "unknown",
            ),
            "dkim": header_analysis.get(
                "dkim",
                "unknown",
            ),
            "dmarc": header_analysis.get(
                "dmarc",
                "unknown",
            ),
            "link_count": record.get(
                "link_count",
                0,
            ),
            "updated_at": record.get(
                "updated_at"
            ),
        }
    )


df = pd.DataFrame(
    rows
)

df["updated_at"] = pd.to_datetime(
    df["updated_at"],
    errors="coerce",
)


filter_col1, filter_col2 = st.columns(
    2
)

risk_filter = filter_col1.selectbox(
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

search_text = filter_col2.text_input(
    "Search subject or sender"
)


filtered_df = df.copy()

if risk_filter != "All":
    filtered_df = filtered_df[
        filtered_df["risk_level"]
        == risk_filter
    ]

if search_text:
    search_value = search_text.lower()

    search_mask = (
        filtered_df["subject"]
        .fillna("")
        .astype(str)
        .str.lower()
        .str.contains(
            search_value,
            regex=False,
        )
        |
        filtered_df["sender"]
        .fillna("")
        .astype(str)
        .str.lower()
        .str.contains(
            search_value,
            regex=False,
        )
    )

    filtered_df = filtered_df[
        search_mask
    ]


st.subheader(
    "Full Email Risk Results"
)

st.dataframe(
    filtered_df,
    width="stretch",
    hide_index=True,
    column_config={
        "gmail_message_id": None,
        "subject": "Subject",
        "sender": "Sender",
        "content_score": (
            st.column_config.NumberColumn(
                "Content",
                format="%.1f",
            )
        ),
        "highest_url_score": (
            st.column_config.NumberColumn(
                "URL",
                format="%.1f",
            )
        ),
        "header_score": (
            st.column_config.NumberColumn(
                "Headers",
                format="%.1f",
            )
        ),
        "combined_score": (
            st.column_config.NumberColumn(
                "Final Score",
                format="%.1f",
            )
        ),
        "risk_level": "Risk",
        "spf": "SPF",
        "dkim": "DKIM",
        "dmarc": "DMARC",
        "link_count": "Links",
        "updated_at": (
            st.column_config.DatetimeColumn(
                "Scanned At",
                format="YYYY-MM-DD HH:mm:ss",
            )
        ),
    },
)


st.subheader(
    "Risk Score Comparison"
)

chart_data = filtered_df[
    [
        "subject",
        "content_score",
        "highest_url_score",
        "header_score",
        "combined_score",
    ]
].head(
    25
)

if not chart_data.empty:
    melted = chart_data.melt(
        id_vars=[
            "subject"
        ],
        var_name="Score Type",
        value_name="Score",
    )

    chart = px.bar(
        melted,
        x="subject",
        y="Score",
        color="Score Type",
        barmode="group",
    )

    st.plotly_chart(
        chart,
        width="stretch",
    )


st.subheader(
    "Inspect a Full Email Analysis"
)

options = {}

for record in history:
    label = (
        f"{record.get('risk_level')} | "
        f"{record.get('subject')} | "
        f"{record.get('sender')}"
    )

    options[
        label
    ] = record


selected_label = st.selectbox(
    "Select an email",
    list(
        options.keys()
    ),
)

selected_record = options[
    selected_label
]

analysis = selected_record.get(
    "analysis",
    {},
)

header_analysis = analysis.get(
    "header_analysis",
    {},
)


metric1, metric2, metric3, metric4 = (
    st.columns(4)
)

metric1.metric(
    "Final Risk",
    (
        f"{selected_record.get('combined_score', 0)}"
        "/100"
    ),
)

metric2.metric(
    "Content",
    (
        f"{selected_record.get('content_score', 0)}"
        "/100"
    ),
)

metric3.metric(
    "Highest URL",
    (
        f"{selected_record.get('highest_url_score', 0)}"
        "/100"
    ),
)

metric4.metric(
    "Headers",
    (
        f"{analysis.get('header_score', 0)}"
        "/100"
    ),
)


auth1, auth2, auth3 = st.columns(
    3
)

auth1.metric(
    "SPF",
    str(
        header_analysis.get(
            "spf",
            "unknown",
        )
    ).upper(),
)

auth2.metric(
    "DKIM",
    str(
        header_analysis.get(
            "dkim",
            "unknown",
        )
    ).upper(),
)

auth3.metric(
    "DMARC",
    str(
        header_analysis.get(
            "dmarc",
            "unknown",
        )
    ).upper(),
)


st.write(
    "**Recommendation**"
)

recommendation = selected_record.get(
    "recommendation",
    "Verify the sender independently.",
)

if selected_record.get(
    "is_phishing"
):
    st.error(
        recommendation
    )

elif selected_record.get(
    "is_suspicious"
):
    st.warning(
        recommendation
    )

else:
    st.success(
        recommendation
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
        "No major phishing reasons were recorded."
    )


with st.expander(
    "View email-header details"
):
    st.json(
        header_analysis
    )


with st.expander(
    "View URL results"
):
    url_results = analysis.get(
        "url_results",
        [],
    )

    if url_results:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "url": item.get(
                            "url"
                        ),
                        "score": item.get(
                            "final_score",
                            0,
                        ),
                        "risk": item.get(
                            "risk_level"
                        ),
                        "phishing": item.get(
                            "is_phishing",
                            False,
                        ),
                    }
                    for item in url_results
                ]
            ),
            width="stretch",
            hide_index=True,
        )

    else:
        st.write(
            "No URLs were detected."
        )


with st.expander(
    "View complete analysis"
):
    st.json(
        analysis
    )


st.info(
    "The final score uses email content, URL behavior, "
    "and sender-authentication results. No single signal "
    "is treated as absolute proof of phishing."
)
