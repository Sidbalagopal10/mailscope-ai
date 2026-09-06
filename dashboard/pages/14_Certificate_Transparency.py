from __future__ import annotations

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Certificate Transparency",
    page_icon="📜",
    layout="wide",
)

st.title(
    "📜 Certificate Transparency Intelligence"
)

st.caption(
    "Search public certificate history for a domain "
    "and its subdomains. Certificate issuance proves "
    "public TLS activity—not organizational legitimacy."
)


def api_get(
    path: str,
):
    response = requests.get(
        f"{API_BASE_URL}{path}",
        timeout=60,
    )

    response.raise_for_status()

    return response.json()


try:
    summary = api_get(
        "/certificate-transparency/summary"
    )

except requests.RequestException as error:
    st.error(
        f"FastAPI is unavailable: {error}"
    )

    st.stop()


col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Observed Domains",
    summary.get(
        "observed_domains",
        0,
    ),
)

col2.metric(
    "Successful Lookups",
    summary.get(
        "successful_lookups",
        0,
    ),
)

col3.metric(
    "Stored Certificates",
    summary.get(
        "stored_certificates",
        0,
    ),
)

col4.metric(
    "Certificate Names",
    summary.get(
        "unique_certificate_names",
        0,
    ),
)


lookup_tab, history_tab = st.tabs(
    [
        "Domain Lookup",
        "Observation History",
    ]
)


with lookup_tab:
    domain = st.text_input(
        "Domain",
        placeholder="example.org",
    )

    include_subdomains = st.checkbox(
        "Include subdomains",
        value=True,
    )

    force_refresh = st.checkbox(
        "Refresh cached result"
    )

    if st.button(
        "Search Certificate History",
        type="primary",
        width="stretch",
    ):
        if not domain.strip():
            st.warning(
                "Enter a domain."
            )

        else:
            try:
                parameters = (
                    f"domain={domain.strip()}"
                    f"&include_subdomains="
                    f"{'true' if include_subdomains else 'false'}"
                    f"&force="
                    f"{'true' if force_refresh else 'false'}"
                )

                result = api_get(
                    "/certificate-transparency/"
                    f"lookup?{parameters}"
                )

                observation = result[
                    "observation"
                ]

                evidence = result[
                    "risk_evidence"
                ]

                if observation.get(
                    "lookup_status"
                ) == "success":
                    st.success(
                        "Certificate Transparency "
                        "history retrieved."
                    )

                else:
                    st.warning(
                        "Certificate Transparency data "
                        "was unavailable."
                    )

                metric1, metric2, metric3, metric4 = st.columns(4)

                metric1.metric(
                    "Certificates",
                    observation.get(
                        "certificate_count",
                        0,
                    ),
                )

                metric2.metric(
                    "Unique Names",
                    observation.get(
                        "unique_name_count",
                        0,
                    ),
                )

                metric3.metric(
                    "First Seen",
                    observation.get(
                        "first_seen"
                    )
                    or "Unknown",
                )

                metric4.metric(
                    "Risk Adjustment",
                    evidence.get(
                        "risk_adjustment",
                        0,
                    ),
                )

                st.subheader(
                    "Certificate Summary"
                )

                st.json(
                    {
                        "domain": observation.get(
                            "domain"
                        ),
                        "first_seen": observation.get(
                            "first_seen"
                        ),
                        "last_seen": observation.get(
                            "last_seen"
                        ),
                        "newest_not_before": observation.get(
                            "newest_not_before"
                        ),
                        "newest_not_after": observation.get(
                            "newest_not_after"
                        ),
                        "newest_issuer_name": observation.get(
                            "newest_issuer_name"
                        ),
                        "newest_common_name": observation.get(
                            "newest_common_name"
                        ),
                        "names": observation.get(
                            "names",
                            [],
                        )[:250],
                        "cache_status": observation.get(
                            "cache_status"
                        ),
                        "error_message": observation.get(
                            "error_message"
                        ),
                    }
                )

                st.subheader(
                    "Bounded Security Evidence"
                )

                st.json(
                    evidence
                )

                st.info(
                    "A new certificate is a weak observation "
                    "only. Legitimate organizations and "
                    "attackers both obtain TLS certificates."
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
            "/certificate-transparency/"
            "observations?limit=1000"
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

        columns = [
            "domain",
            "lookup_status",
            "certificate_count",
            "unique_name_count",
            "first_seen",
            "last_seen",
            "newest_issuer_name",
            "observed_at",
        ]

        available_columns = [
            column
            for column in columns
            if column in frame.columns
        ]

        st.dataframe(
            frame[
                available_columns
            ],
            width="stretch",
            hide_index=True,
        )

    else:
        st.info(
            "No Certificate Transparency "
            "lookups have been stored yet."
        )
