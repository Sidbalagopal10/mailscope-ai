from __future__ import annotations

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Trusted Domains",
    page_icon="✅",
    layout="wide",
)

st.title("✅ Trusted and Blocked Domains")

st.caption(
    "Reduce false positives for authenticated banks, employers, "
    "universities, and services while preserving phishing checks."
)


def api_get(
    endpoint: str,
):
    response = requests.get(
        f"{API_BASE_URL}{endpoint}",
        timeout=30,
    )

    response.raise_for_status()

    return response.json()


def api_post(
    endpoint: str,
    payload: dict | None = None,
):
    response = requests.post(
        f"{API_BASE_URL}{endpoint}",
        json=payload,
        timeout=60,
    )

    response.raise_for_status()

    return response.json()


if st.button(
    "Add Recommended Starter Domains",
    width="stretch",
):
    try:
        result = api_post(
            "/domain-trust/seed-recommended"
        )

        st.success(
            f"Processed {result['records_processed']} "
            "recommended domains."
        )

        st.rerun()

    except requests.RequestException as error:
        st.error(
            f"Unable to seed domains: {error}"
        )


with st.form(
    "domain_trust_form"
):
    col1, col2 = st.columns(2)

    domain = col1.text_input(
        "Domain",
        placeholder="example.com",
    )

    status = col2.selectbox(
        "Status",
        [
            "TRUSTED",
            "UNKNOWN",
            "BLOCKED",
        ],
    )

    category = st.selectbox(
        "Category",
        [
            "",
            "financial",
            "jobs",
            "university",
            "technology",
            "commerce",
            "newsletter",
            "government",
            "other",
        ],
    )

    notes = st.text_area(
        "Notes",
        placeholder=(
            "Why is this domain trusted or blocked?"
        ),
    )

    save_clicked = st.form_submit_button(
        "Save Domain",
        type="primary",
        width="stretch",
    )


if save_clicked:
    try:
        api_post(
            "/domain-trust",
            {
                "domain": domain,
                "status": status,
                "category": category or None,
                "notes": notes or None,
            },
        )

        st.success(
            "Domain saved."
        )

        st.rerun()

    except requests.HTTPError as error:
        try:
            detail = error.response.json().get(
                "detail",
                str(error),
            )
        except ValueError:
            detail = str(error)

        st.error(
            detail
        )

    except requests.RequestException as error:
        st.error(
            f"Unable to save the domain: {error}"
        )


try:
    records = api_get(
        "/domain-trust"
    ).get(
        "domains",
        [],
    )

except requests.RequestException as error:
    st.error(
        f"Unable to load domains: {error}"
    )

    st.stop()


metric1, metric2, metric3 = st.columns(3)

metric1.metric(
    "Trusted",
    sum(
        1
        for record in records
        if record["status"]
        == "TRUSTED"
    ),
)

metric2.metric(
    "Unknown",
    sum(
        1
        for record in records
        if record["status"]
        == "UNKNOWN"
    ),
)

metric3.metric(
    "Blocked",
    sum(
        1
        for record in records
        if record["status"]
        == "BLOCKED"
    ),
)


if records:
    st.dataframe(
        pd.DataFrame(
            records
        ),
        width="stretch",
        hide_index=True,
    )

    st.subheader(
        "Remove a Domain"
    )

    options = {
        (
            f"{record['status']} | "
            f"{record['domain']} | "
            f"{record.get('category') or 'uncategorized'}"
        ): record["id"]
        for record in records
    }

    selected = st.selectbox(
        "Domain record",
        list(
            options.keys()
        ),
    )

    confirm = st.checkbox(
        "Confirm removal"
    )

    if st.button(
        "Remove Selected Domain",
        disabled=not confirm,
        width="stretch",
    ):
        response = requests.delete(
            (
                f"{API_BASE_URL}"
                "/domain-trust/"
                f"{options[selected]}"
            ),
            timeout=30,
        )

        response.raise_for_status()

        st.success(
            "Domain removed."
        )

        st.rerun()

else:
    st.info(
        "No domain-trust records exist yet."
    )


st.warning(
    "Trusted status does not bypass security analysis. "
    "Risk reduction applies only when SPF, DKIM, and DMARC "
    "pass and no major alignment or impersonation problem exists."
)
