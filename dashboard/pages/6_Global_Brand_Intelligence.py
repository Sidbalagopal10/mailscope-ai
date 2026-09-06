from __future__ import annotations

from urllib.parse import quote

import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Global Brand Intelligence",
    page_icon="🎭",
    layout="wide",
)

st.title(
    "🎭 Global Brand Intelligence"
)

st.caption(
    "Detect typosquatting and brand use on unofficial "
    "domains using the worldwide Organization Intelligence registry."
)


def api_get(path: str):
    response = requests.get(
        f"{API_BASE_URL}{path}",
        timeout=60,
    )

    response.raise_for_status()

    return response.json()


def api_post(path: str):
    response = requests.post(
        f"{API_BASE_URL}{path}",
        timeout=300,
    )

    response.raise_for_status()

    return response.json()


try:
    summary = api_get(
        "/global-brand-intelligence/summary"
    )

except requests.RequestException as error:
    st.error(
        f"FastAPI is unavailable: {error}"
    )
    st.stop()


column1, column2, column3, column4 = st.columns(4)

column1.metric(
    "Brands",
    summary.get(
        "brands",
        0,
    ),
)

column2.metric(
    "Aliases",
    summary.get(
        "aliases",
        0,
    ),
)

column3.metric(
    "Official Domains",
    summary.get(
        "official_domains",
        0,
    ),
)

column4.metric(
    "Countries",
    summary.get(
        "countries",
        0,
    ),
)


if st.button(
    "Rebuild Global Brand Index",
    width="stretch",
):
    with st.spinner(
        "Building aliases from Organization Intelligence..."
    ):
        try:
            result = api_post(
                "/global-brand-intelligence/rebuild"
            )

            st.success(
                "Global brand index rebuilt."
            )

            st.json(
                result
            )

            st.rerun()

        except requests.RequestException as error:
            st.error(
                str(error)
            )


domain = st.text_input(
    "Domain or URL",
    placeholder="applee.com",
)

if st.button(
    "Analyze Brand Impersonation",
    type="primary",
    width="stretch",
):
    if not domain.strip():
        st.warning(
            "Enter a domain."
        )

    else:
        try:
            result = api_get(
                "/global-brand-intelligence/analyze"
                f"?domain={quote(domain.strip(), safe='')}"
            )

            if result[
                "impersonation_detected"
            ]:
                st.error(
                    "Possible brand impersonation detected."
                )

            else:
                st.success(
                    "No indexed brand impersonation was detected."
                )

            strongest = (
                result.get(
                    "strongest_finding"
                )
                or {}
            )

            metric1, metric2, metric3, metric4 = st.columns(4)

            metric1.metric(
                "Detected",
                (
                    "YES"
                    if result[
                        "impersonation_detected"
                    ]
                    else "NO"
                ),
            )

            metric2.metric(
                "Brand",
                strongest.get(
                    "brand_name",
                    "None",
                ),
            )

            metric3.metric(
                "Similarity",
                (
                    f"{strongest.get('similarity', 0) * 100:.1f}%"
                    if strongest
                    else "0%"
                ),
            )

            metric4.metric(
                "Risk Adjustment",
                result.get(
                    "risk_adjustment",
                    0,
                ),
            )

            st.json(
                result
            )

        except requests.RequestException as error:
            st.error(
                str(error)
            )
