from __future__ import annotations

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Global Domain Intelligence",
    page_icon="🌍",
    layout="wide",
)

st.title(
    "🌍 Global Domain Intelligence"
)

st.caption(
    "Retrieve structured registration evidence through "
    "authoritative RDAP services. Newness is treated as "
    "limited history—not automatic proof of phishing."
)


def api_get(
    path: str,
):
    response = requests.get(
        f"{API_BASE_URL}{path}",
        timeout=40,
    )

    response.raise_for_status()

    return response.json()


try:
    summary = api_get(
        "/domain-intelligence/summary"
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
    "Successful RDAP",
    summary.get(
        "successful_lookups",
        0,
    ),
)

col3.metric(
    "30 Days or Newer",
    summary.get(
        "domains_age_30_days_or_less",
        0,
    ),
)

col4.metric(
    "DNSSEC Signed",
    summary.get(
        "dnssec_signed",
        0,
    ),
)


lookup_tab, history_tab, coverage_tab = st.tabs(
    [
        "RDAP Lookup",
        "Observation History",
        "TLD Coverage",
    ]
)


with lookup_tab:
    domain = st.text_input(
        "Domain",
        placeholder="example.org",
    )

    force_refresh = st.checkbox(
        "Refresh cached RDAP data"
    )

    if st.button(
        "Enrich Domain",
        type="primary",
        width="stretch",
    ):
        if not domain.strip():
            st.warning(
                "Enter a domain."
            )

        else:
            try:
                payload = api_get(
                    (
                        "/domain-intelligence/rdap"
                        f"?domain={domain.strip()}"
                        f"&force={'true' if force_refresh else 'false'}"
                    )
                )

                observation = payload[
                    "observation"
                ]

                evidence = payload[
                    "risk_evidence"
                ]

                if (
                    observation.get(
                        "lookup_status"
                    )
                    == "success"
                ):
                    st.success(
                        "Authoritative RDAP evidence retrieved."
                    )

                else:
                    st.warning(
                        "RDAP evidence was unavailable for this domain."
                    )

                metric1, metric2, metric3, metric4 = st.columns(4)

                metric1.metric(
                    "Domain Age",
                    (
                        f"{observation['domain_age_days']} days"
                        if observation.get(
                            "domain_age_days"
                        )
                        is not None
                        else "Unknown"
                    ),
                )

                metric2.metric(
                    "DNSSEC",
                    observation.get(
                        "dnssec_state",
                        "unknown",
                    ).upper(),
                )

                metric3.metric(
                    "Registrar",
                    observation.get(
                        "registrar_name"
                    )
                    or "Not public",
                )

                metric4.metric(
                    "Risk Adjustment",
                    evidence.get(
                        "risk_adjustment",
                        0,
                    ),
                )

                st.subheader(
                    "Registration Evidence"
                )

                st.json(
                    {
                        "domain": observation.get(
                            "domain"
                        ),
                        "tld": observation.get(
                            "tld"
                        ),
                        "registration_date": observation.get(
                            "registration_date"
                        ),
                        "last_changed_date": observation.get(
                            "last_changed_date"
                        ),
                        "expiration_date": observation.get(
                            "expiration_date"
                        ),
                        "registrar_name": observation.get(
                            "registrar_name"
                        ),
                        "registrar_handle": observation.get(
                            "registrar_handle"
                        ),
                        "domain_status": observation.get(
                            "domain_status"
                        ),
                        "nameservers": observation.get(
                            "nameservers"
                        ),
                        "rdap_server": observation.get(
                            "rdap_server"
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
                    "Bounded Security Evidence"
                )

                st.json(
                    evidence
                )

                st.info(
                    "RDAP proves registration facts where public. "
                    "It does not prove that a website is legitimate, "
                    "safe, uncompromised, or connected to a claimed "
                    "organization."
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
            "/domain-intelligence/observations?limit=1000"
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
        visible_columns = [
            "domain",
            "tld",
            "lookup_status",
            "registration_date",
            "domain_age_days",
            "registrar_name",
            "dnssec_state",
            "observed_at",
        ]

        frame = pd.DataFrame(
            observations
        )

        available_columns = [
            column
            for column in visible_columns
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
            "No domains have been enriched yet."
        )


with coverage_tab:
    top_tlds = summary.get(
        "top_tlds",
        {},
    )

    if top_tlds:
        coverage_frame = pd.DataFrame(
            [
                {
                    "TLD": tld,
                    "Observed Domains": count,
                }
                for tld, count in top_tlds.items()
            ]
        )

        st.dataframe(
            coverage_frame,
            width="stretch",
            hide_index=True,
        )

    else:
        st.info(
            "TLD coverage will appear after RDAP lookups."
        )
