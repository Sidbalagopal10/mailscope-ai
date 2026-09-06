from __future__ import annotations

from urllib.parse import quote

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="VirusTotal Intelligence",
    page_icon="🧪",
    layout="wide",
)

st.title(
    "🧪 VirusTotal Reputation Intelligence"
)

st.caption(
    "Selective, cached URL, domain, and IP reputation. "
    "No URL is submitted for scanning."
)

st.warning(
    "The VirusTotal public API is quota limited. "
    "Use Force refresh only when necessary."
)


def api_get(
    path: str,
    *,
    timeout: int = 180,
):
    response = requests.get(
        f"{API_BASE_URL}{path}",
        timeout=timeout,
    )

    response.raise_for_status()

    return response.json()


try:
    summary = api_get(
        "/virustotal/summary"
    )

except requests.RequestException as error:
    st.error(
        f"FastAPI is unavailable: {error}"
    )

    st.stop()


column1, column2, column3, column4 = st.columns(4)

column1.metric(
    "Observed Indicators",
    summary.get(
        "observed_indicators",
        0,
    ),
)

column2.metric(
    "Detected",
    summary.get(
        "detected_indicators",
        0,
    ),
)

column3.metric(
    "Successful",
    summary.get(
        "successful_lookups",
        0,
    ),
)

column4.metric(
    "Failed",
    summary.get(
        "failed_lookups",
        0,
    ),
)


lookup_tab, history_tab = st.tabs(
    [
        "Reputation Lookup",
        "Cached History",
    ]
)


with lookup_tab:
    indicator = st.text_input(
        "URL, domain, or IP address",
        placeholder="https://example.com/login",
    )

    force_refresh = st.checkbox(
        "Force VirusTotal refresh"
    )

    if st.button(
        "Check VirusTotal",
        type="primary",
        width="stretch",
    ):
        if not indicator.strip():
            st.warning(
                "Enter an indicator."
            )

        else:
            try:
                if indicator.lower().startswith(
                    (
                        "http://",
                        "https://",
                    )
                ):
                    payload = api_get(
                        (
                            "/virustotal/lookup-url"
                            f"?url={quote(indicator.strip(), safe='')}"
                            f"&force="
                            f"{'true' if force_refresh else 'false'}"
                        )
                    )

                    evidence = payload.get(
                        "combined_evidence",
                        {},
                    )

                    lookup_result = payload.get(
                        "lookup",
                        {},
                    )

                    url_result = lookup_result.get(
                        "url_result",
                        {},
                    )

                    domain_result = lookup_result.get(
                        "domain_result",
                        {},
                    )

                    matched = evidence.get(
                        "matched",
                        False,
                    )

                    st.error(
                        "VirusTotal detections were found."
                    ) if matched else st.info(
                        "No VirusTotal malicious or suspicious "
                        "detections were found."
                    )

                    metric1, metric2, metric3, metric4 = st.columns(4)

                    metric1.metric(
                        "Risk Adjustment",
                        evidence.get(
                            "risk_adjustment",
                            0,
                        ),
                    )

                    metric2.metric(
                        "URL Malicious",
                        url_result.get(
                            "malicious",
                            0,
                        ),
                    )

                    metric3.metric(
                        "Domain Malicious",
                        domain_result.get(
                            "malicious",
                            0,
                        ),
                    )

                    metric4.metric(
                        "Cache",
                        (
                            f"URL: {url_result.get('cache_status', 'unknown')} / "
                            f"Domain: {domain_result.get('cache_status', 'unknown')}"
                        ),
                    )

                    st.subheader(
                        "Combined Evidence"
                    )

                    st.json(
                        evidence
                    )

                else:
                    payload = api_get(
                        (
                            "/virustotal/lookup"
                            f"?indicator={quote(indicator.strip(), safe='')}"
                            f"&force="
                            f"{'true' if force_refresh else 'false'}"
                        )
                    )

                    observation = payload.get(
                        "observation",
                        {},
                    )

                    evidence = payload.get(
                        "risk_evidence",
                        {},
                    )

                    if evidence.get(
                        "matched"
                    ):
                        st.error(
                            "VirusTotal detections were found."
                        )

                    else:
                        st.info(
                            "No VirusTotal malicious or suspicious "
                            "detections were found."
                        )

                    metric1, metric2, metric3, metric4 = st.columns(4)

                    metric1.metric(
                        "Malicious",
                        observation.get(
                            "malicious",
                            0,
                        ),
                    )

                    metric2.metric(
                        "Suspicious",
                        observation.get(
                            "suspicious",
                            0,
                        ),
                    )

                    metric3.metric(
                        "Total Engines",
                        observation.get(
                            "total_engines",
                            0,
                        ),
                    )

                    metric4.metric(
                        "Risk Adjustment",
                        evidence.get(
                            "risk_adjustment",
                            0,
                        ),
                    )

                    st.json(
                        {
                            "observation": observation,
                            "risk_evidence": evidence,
                        }
                    )

            except requests.HTTPError as error:
                try:
                    detail = (
                        error.response.json().get(
                            "detail"
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
                    str(
                        error
                    )
                )


with history_tab:
    try:
        observations = api_get(
            "/virustotal/observations?limit=1000"
        ).get(
            "observations",
            [],
        )

    except requests.RequestException as error:
        st.error(
            str(
                error
            )
        )

        observations = []

    if observations:
        frame = pd.DataFrame(
            observations
        )

        visible = [
            "indicator",
            "indicator_type",
            "lookup_status",
            "object_found",
            "malicious",
            "suspicious",
            "harmless",
            "total_engines",
            "reputation",
            "observed_at",
            "expires_at",
        ]

        columns = [
            column
            for column in visible
            if column in frame.columns
        ]

        st.dataframe(
            frame[
                columns
            ],
            width="stretch",
            hide_index=True,
        )

    else:
        st.info(
            "No VirusTotal observations have been cached."
        )
