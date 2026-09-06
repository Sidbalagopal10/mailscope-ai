from __future__ import annotations

from urllib.parse import quote

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="ThreatFox Intelligence",
    page_icon="🦊",
    layout="wide",
)

st.title(
    "🦊 ThreatFox Malware IOC Intelligence"
)

st.caption(
    "Search malware-associated indicators from ThreatFox. "
    "No-match results are neutral and do not prove safety."
)


def api_get(
    path: str,
    *,
    timeout: int = 60,
):
    response = requests.get(
        f"{API_BASE_URL}{path}",
        timeout=timeout,
    )

    response.raise_for_status()

    return response.json()


try:
    summary = api_get(
        "/threatfox/summary"
    )

except requests.RequestException as error:
    st.error(
        f"FastAPI is unavailable: {error}"
    )

    st.stop()


col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Observed Indicators",
    summary.get(
        "observed_indicators",
        0,
    ),
)

col2.metric(
    "Threat Matches",
    summary.get(
        "matched_indicators",
        0,
    ),
)

col3.metric(
    "Unmatched",
    summary.get(
        "clean_or_unmatched",
        0,
    ),
)

col4.metric(
    "Failed Lookups",
    summary.get(
        "failed_lookups",
        0,
    ),
)


lookup_tab, history_tab = st.tabs(
    [
        "IOC Lookup",
        "Observation History",
    ]
)


with lookup_tab:
    indicator = st.text_input(
        "URL, domain, or IP address",
        placeholder="example.org",
    )

    force_refresh = st.checkbox(
        "Refresh cached ThreatFox result"
    )

    if st.button(
        "Search ThreatFox",
        type="primary",
        width="stretch",
    ):
        if not indicator.strip():
            st.warning(
                "Enter an indicator."
            )

        else:
            try:
                payload = api_get(
                    (
                        "/threatfox/lookup"
                        f"?indicator={quote(indicator.strip(), safe='')}"
                        f"&force="
                        f"{'true' if force_refresh else 'false'}"
                    )
                )

                observation = payload[
                    "observation"
                ]

                evidence = payload[
                    "risk_evidence"
                ]

                if observation.get(
                    "lookup_status"
                ) != "success":
                    st.warning(
                        "ThreatFox was unavailable. "
                        "No risk was added."
                    )

                elif observation.get(
                    "matched"
                ):
                    st.error(
                        "ThreatFox malware-associated IOC match found."
                    )

                else:
                    st.info(
                        "No active ThreatFox match was found."
                    )

                metric1, metric2, metric3, metric4 = st.columns(4)

                metric1.metric(
                    "Matched",
                    (
                        "YES"
                        if observation.get(
                            "matched"
                        )
                        else "NO"
                    ),
                )

                metric2.metric(
                    "Matches",
                    observation.get(
                        "match_count",
                        0,
                    ),
                )

                metric3.metric(
                    "Maximum Confidence",
                    (
                        f"{observation.get('maximum_confidence', 0)}%"
                    ),
                )

                metric4.metric(
                    "Risk Adjustment",
                    evidence.get(
                        "risk_adjustment",
                        0,
                    ),
                )

                st.subheader(
                    "Threat Summary"
                )

                st.json(
                    {
                        "indicator": observation.get(
                            "indicator"
                        ),
                        "indicator_type": observation.get(
                            "indicator_type"
                        ),
                        "query_status": observation.get(
                            "query_status"
                        ),
                        "malware_families": observation.get(
                            "malware_families"
                        ),
                        "threat_types": observation.get(
                            "threat_types"
                        ),
                        "cache_status": observation.get(
                            "cache_status"
                        ),
                        "error_message": observation.get(
                            "error_message"
                        ),
                    }
                )

                st.subheader(
                    "IOC Matches"
                )

                matches = observation.get(
                    "matches",
                    [],
                )

                if matches:
                    st.dataframe(
                        pd.DataFrame(
                            matches
                        ),
                        width="stretch",
                        hide_index=True,
                    )

                else:
                    st.write(
                        "No matching IOC records."
                    )

                st.subheader(
                    "Bounded Security Evidence"
                )

                st.json(
                    evidence
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
            "/threatfox/observations?limit=1000"
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
            "matched",
            "match_count",
            "maximum_confidence",
            "malware_families",
            "threat_types",
            "observed_at",
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
            "No ThreatFox observations have been stored yet."
        )
