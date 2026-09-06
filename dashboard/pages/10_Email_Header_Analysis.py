from __future__ import annotations

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Email Header Analysis",
    page_icon="🔐",
    layout="wide",
)

st.title("🔐 Email Authentication Analysis")

st.caption(
    "Inspect recent Gmail messages for SPF, DKIM, DMARC, "
    "Reply-To mismatches, and Return-Path mismatches."
)


limit = st.number_input(
    "Recent Gmail messages to analyze",
    min_value=1,
    max_value=50,
    value=10,
    step=1,
)

if st.button(
    "Analyze Email Headers",
    type="primary",
    width="stretch",
):
    with st.spinner("Reading Gmail authentication headers..."):
        try:
            response = requests.get(
                f"{API_BASE_URL}/header-analysis/recent",
                params={"limit": int(limit)},
                timeout=180,
            )
            response.raise_for_status()

            st.session_state["header_analysis_results"] = (
                response.json()
            )

        except requests.ConnectionError:
            st.error("FastAPI is not running.")

        except requests.Timeout:
            st.error("Header analysis timed out.")

        except requests.HTTPError as error:
            try:
                detail = error.response.json().get(
                    "detail",
                    str(error),
                )
            except ValueError:
                detail = str(error)

            st.error(detail)

        except requests.RequestException as error:
            st.error(f"Analysis failed: {error}")


data = st.session_state.get("header_analysis_results")

if not data:
    st.info(
        "Click Analyze Email Headers to inspect recent messages."
    )
    st.stop()


results = data.get("results", [])

metric1, metric2 = st.columns(2)

metric1.metric(
    "Emails Analyzed",
    data.get("emails_analyzed", 0),
)

metric2.metric(
    "Suspicious Headers",
    data.get("suspicious_emails", 0),
)

if not results:
    st.info("No email results were returned.")
    st.stop()


table = pd.DataFrame(
    [
        {
            "subject": item.get("subject"),
            "from_address": item.get("from_address"),
            "spf": item.get("spf"),
            "dkim": item.get("dkim"),
            "dmarc": item.get("dmarc"),
            "reply_to_mismatch": item.get("reply_to_mismatch"),
            "return_path_mismatch": item.get(
                "return_path_mismatch"
            ),
            "header_score": item.get("header_score"),
            "risk_level": item.get("risk_level"),
        }
        for item in results
    ]
)

st.subheader("Authentication Results")

st.dataframe(
    table,
    width="stretch",
    hide_index=True,
)

st.subheader("Inspect an Email")

options = {
    (
        f"{item.get('risk_level')} | "
        f"{item.get('subject')} | "
        f"{item.get('from_address')}"
    ): item
    for item in results
}

selected_label = st.selectbox(
    "Select a message",
    list(options.keys()),
)

selected = options[selected_label]

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Header Risk",
    f"{selected.get('header_score', 0)}/100",
)
col2.metric("SPF", str(selected.get("spf", "none")).upper())
col3.metric("DKIM", str(selected.get("dkim", "none")).upper())
col4.metric("DMARC", str(selected.get("dmarc", "none")).upper())

st.write("**Sender alignment**")
st.write("From domain:", selected.get("from_domain") or "Unknown")
st.write(
    "Reply-To domain:",
    selected.get("reply_to_domain") or "Not supplied",
)
st.write(
    "Return-Path domain:",
    selected.get("return_path_domain") or "Not supplied",
)

st.write("**Recommendation**")

if selected.get("is_suspicious"):
    st.warning(selected.get("recommendation"))
else:
    st.success(selected.get("recommendation"))

st.write("**Reasons**")

for reason in selected.get("reasons", []):
    st.write(f"- {reason}")

with st.expander("View raw header analysis"):
    st.json(selected)

st.info(
    "Authentication failures are risk signals, not absolute proof "
    "of phishing. Forwarding and mailing lists can affect results."
)
