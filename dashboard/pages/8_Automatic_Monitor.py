from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"
LOG_PATH = Path("logs/gmail_monitor.log")


st.set_page_config(
    page_title="Automatic Gmail Monitor",
    page_icon="🔄",
    layout="wide",
)

st.title("🔄 Automatic Gmail Monitor")

st.caption(
    "The background worker checks for new Gmail messages, "
    "analyzes email content and URLs, saves the results, "
    "and applies an AI Security risk label."
)


try:
    response = requests.get(
        f"{API_BASE_URL}/monitor/summary",
        timeout=20,
    )

    response.raise_for_status()
    summary = response.json()

except requests.ConnectionError:
    st.error(
        "FastAPI is not running."
    )

    st.stop()

except requests.RequestException as error:
    st.error(
        f"Unable to load monitor status: {error}"
    )

    st.stop()


col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Processed Messages",
    summary.get(
        "total_processed",
        0,
    ),
)

col2.metric(
    "Completed",
    summary.get(
        "completed",
        0,
    ),
)

col3.metric(
    "Failed",
    summary.get(
        "failed",
        0,
    ),
)

col4.metric(
    "Last Activity",
    summary.get(
        "last_activity"
    )
    or "Not started",
)


st.subheader(
    "Risk Distribution"
)

distribution = pd.DataFrame(
    [
        {
            "risk_level": risk_level,
            "count": count,
        }
        for risk_level, count
        in summary.get(
            "risk_distribution",
            {},
        ).items()
    ]
)

if not distribution.empty:
    chart = px.bar(
        distribution,
        x="risk_level",
        y="count",
        color="risk_level",
    )

    st.plotly_chart(
        chart,
        width="stretch",
    )

else:
    st.info(
        "No automatically processed messages yet."
    )


st.subheader(
    "Monitor Log"
)

if st.button(
    "Refresh Monitor Status",
    type="primary",
):
    st.rerun()


if LOG_PATH.exists():
    lines = LOG_PATH.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines()

    recent_lines = lines[-150:]

    st.code(
        "\n".join(
            recent_lines
        ),
        language="text",
    )

else:
    st.info(
        "The monitor log has not been created yet."
    )


st.divider()

st.info(
    "The local monitor runs only while run_app.sh is active. "
    "A cloud deployment or Gmail push-notification service "
    "would be needed for continuous operation while your "
    "Mac is turned off."
)
