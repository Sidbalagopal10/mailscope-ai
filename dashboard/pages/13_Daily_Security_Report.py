from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"

REPORT_DIRECTORY = Path(
    "reports/daily"
)


st.set_page_config(
    page_title="Daily Security Report",
    page_icon="📋",
    layout="wide",
)

st.title("📋 Daily Security Report")

st.caption(
    "Daily overview of analyzed emails, phishing risks, "
    "automatic monitoring, and verified feedback."
)


if st.button(
    "Generate Report Now",
    type="primary",
    width="stretch",
):
    with st.spinner(
        "Generating the security report..."
    ):
        try:
            response = requests.post(
                (
                    f"{API_BASE_URL}"
                    "/daily-report/generate"
                ),
                timeout=300,
            )

            response.raise_for_status()

            st.session_state[
                "daily_security_report"
            ] = response.json()

            st.success(
                "Daily security report generated."
            )

        except requests.ConnectionError:
            st.error(
                "FastAPI is not running."
            )

        except requests.Timeout:
            st.error(
                "Report generation timed out."
            )

        except requests.RequestException as error:
            st.error(
                f"Report generation failed: {error}"
            )


if (
    "daily_security_report"
    not in st.session_state
):
    try:
        response = requests.get(
            (
                f"{API_BASE_URL}"
                "/daily-report/latest"
            ),
            timeout=30,
        )

        response.raise_for_status()

        latest = response.json()

        if latest.get(
            "status"
        ) != "not_generated":
            st.session_state[
                "daily_security_report"
            ] = latest

    except requests.RequestException:
        pass


report = st.session_state.get(
    "daily_security_report"
)


if not report:
    st.info(
        "No report has been generated yet."
    )

    st.stop()


st.write(
    "**Report date:**",
    report.get(
        "report_date",
        "Unknown",
    ),
)

st.write(
    "**Generated at:**",
    report.get(
        "generated_at",
        "Unknown",
    ),
)


email_security = report.get(
    "email_security",
    {},
)

metric1, metric2, metric3, metric4 = (
    st.columns(4)
)

metric1.metric(
    "Emails Analyzed",
    email_security.get(
        "emails_analyzed",
        0,
    ),
)

metric2.metric(
    "Suspicious Emails",
    email_security.get(
        "suspicious_emails",
        0,
    ),
)

metric3.metric(
    "Likely Phishing",
    email_security.get(
        "likely_phishing_emails",
        0,
    ),
)

metric4.metric(
    "Highest Risk",
    (
        f"{email_security.get('highest_risk_score', 0)}"
        "/100"
    ),
)


metric5, metric6, metric7 = (
    st.columns(3)
)

metric5.metric(
    "Average Risk",
    (
        f"{email_security.get('average_risk_score', 0)}"
        "/100"
    ),
)

metric6.metric(
    "Links Inspected",
    email_security.get(
        "total_links",
        0,
    ),
)

metric7.metric(
    "Suspicious URLs",
    email_security.get(
        "suspicious_urls",
        0,
    ),
)


st.subheader(
    "Risk Distribution"
)

distribution = pd.DataFrame(
    [
        {
            "Risk Level": level,
            "Count": count,
        }
        for level, count
        in email_security.get(
            "risk_distribution",
            {},
        ).items()
    ]
)

if not distribution.empty:
    chart = px.bar(
        distribution,
        x="Risk Level",
        y="Count",
        color="Risk Level",
    )

    st.plotly_chart(
        chart,
        width="stretch",
    )

else:
    st.info(
        "No risk distribution data is available."
    )


st.subheader(
    "Top-Risk Messages"
)

top_messages = report.get(
    "top_risk_messages",
    [],
)

if top_messages:
    st.dataframe(
        pd.DataFrame(
            top_messages
        ),
        width="stretch",
        hide_index=True,
    )

else:
    st.success(
        "No suspicious messages were included "
        "in this report."
    )


st.subheader(
    "Verified Feedback"
)

feedback = report.get(
    "feedback",
    {},
)

feedback1, feedback2, feedback3, feedback4 = (
    st.columns(4)
)

feedback1.metric(
    "Total Feedback",
    feedback.get(
        "total_feedback",
        0,
    ),
)

feedback2.metric(
    "Correct",
    feedback.get(
        "correct_predictions",
        0,
    ),
)

feedback3.metric(
    "Incorrect",
    feedback.get(
        "incorrect_predictions",
        0,
    ),
)

verified_accuracy = float(
    feedback.get(
        "verified_accuracy",
        0,
    )
    or 0
)

if verified_accuracy <= 1:
    verified_accuracy *= 100

feedback4.metric(
    "Verified Accuracy",
    f"{verified_accuracy:.1f}%",
)


st.subheader(
    "Automatic Monitor"
)

monitor = report.get(
    "automatic_monitor",
    {},
)

monitor1, monitor2, monitor3 = (
    st.columns(3)
)

monitor1.metric(
    "Processed",
    monitor.get(
        "total_processed",
        0,
    ),
)

monitor2.metric(
    "Completed",
    monitor.get(
        "completed",
        0,
    ),
)

monitor3.metric(
    "Failed",
    monitor.get(
        "failed",
        0,
    ),
)


serialized = json.dumps(
    report,
    indent=2,
    ensure_ascii=False,
    default=str,
)

st.download_button(
    "Download Report as JSON",
    data=serialized,
    file_name=(
        "daily_security_report_"
        f"{report.get('report_date', 'latest')}.json"
    ),
    mime="application/json",
    width="stretch",
)


with st.expander(
    "View complete report"
):
    st.json(
        report
    )


st.info(
    "The automatic report is generated at 7:00 PM local time "
    "while the project application is running."
)
