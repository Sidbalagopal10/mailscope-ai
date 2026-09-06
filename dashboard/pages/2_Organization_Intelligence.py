from __future__ import annotations

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Organization Intelligence",
    page_icon="🏢",
    layout="wide",
)

st.title(
    "🏢 Organization–Domain Intelligence"
)

st.caption(
    "Associate organizations with domains using "
    "source-backed identity evidence. Registry identity "
    "does not automatically prove that a domain is safe."
)


def api_get(
    path: str,
):
    response = requests.get(
        f"{API_BASE_URL}{path}",
        timeout=30,
    )

    response.raise_for_status()

    return response.json()


def api_post(
    path: str,
    payload: dict,
):
    response = requests.post(
        f"{API_BASE_URL}{path}",
        json=payload,
        timeout=60,
    )

    response.raise_for_status()

    return response.json()


try:
    summary = api_get(
        "/organization-intelligence/summary"
    )

except requests.RequestException as error:
    st.error(
        f"FastAPI is unavailable: {error}"
    )

    st.stop()


col1, col2, col3 = st.columns(3)

col1.metric(
    "Organizations",
    summary.get(
        "organizations",
        0,
    ),
)

col2.metric(
    "Mapped Domains",
    summary.get(
        "domains",
        0,
    ),
)

col3.metric(
    "Authoritative Evidence",
    summary.get(
        "authoritative_evidence_records",
        0,
    ),
)


lookup_tab, add_tab, import_tab, records_tab = st.tabs(
    [
        "Resolve Domain",
        "Add Evidence",
        "Import Dataset",
        "Registry Records",
    ]
)


with lookup_tab:
    hostname = st.text_input(
        "Hostname",
        placeholder="stanford.edu",
    )

    if st.button(
        "Resolve Organization",
        type="primary",
        width="stretch",
    ):
        if not hostname.strip():
            st.warning(
                "Enter a domain."
            )

        else:
            try:
                result = api_get(
                    (
                        "/organization-intelligence/"
                        "resolve?hostname="
                        f"{hostname.strip()}"
                    )
                )

                if result[
                    "matched"
                ]:
                    st.success(
                        "Organization-domain evidence found."
                    )

                    st.json(
                        result
                    )

                else:
                    st.info(
                        "No registry match was found. "
                        "Unknown identity adds no risk."
                    )

                    st.json(
                        result
                    )

            except requests.RequestException as error:
                st.error(
                    str(
                        error
                    )
                )


with add_tab:
    with st.form(
        "organization_domain_form"
    ):
        legal_name = st.text_input(
            "Legal organization name"
        )

        domain = st.text_input(
            "Official or reported domain"
        )

        entity_type = st.selectbox(
            "Entity type",
            [
                "university",
                "school",
                "bank",
                "government",
                "business",
                "corporation",
                "startup",
                "technology",
                "defense",
                "hospital",
                "nonprofit",
                "unknown",
            ],
        )

        source_name = st.text_input(
            "Source name",
            placeholder=(
                "NCES IPEDS, FDIC BankFind, "
                "GLEIF, government registry"
            ),
        )

        source_type = st.text_input(
            "Source type",
            value="registry",
        )

        source_record_id = st.text_input(
            "Source record ID"
        )

        source_url = st.text_input(
            "Source reference URL"
        )

        col_a, col_b = st.columns(2)

        country_code = col_a.text_input(
            "Country code",
            placeholder="US",
        )

        jurisdiction = col_b.text_input(
            "Jurisdiction"
        )

        identity_state = st.selectbox(
            "Identity state",
            [
                "PROVISIONAL",
                "VERIFIED_NEW",
                "VERIFIED_ESTABLISHED",
                "OBSERVED_LEGITIMATE",
                "UNKNOWN",
                "SUSPICIOUS",
            ],
        )

        security_state = st.selectbox(
            "Security state",
            [
                "NEUTRAL",
                "CLEAN",
                "SUSPICIOUS",
                "KNOWN_MALICIOUS",
                "COMPROMISED_LEGITIMATE",
            ],
        )

        col_c, col_d = st.columns(2)

        identity_confidence = col_c.slider(
            "Identity confidence",
            0,
            100,
            50,
        )

        security_confidence = col_d.slider(
            "Security confidence",
            0,
            100,
            25,
        )

        authoritative = st.checkbox(
            "This is an authoritative source"
        )

        submitted = st.form_submit_button(
            "Save Organization Evidence",
            type="primary",
            width="stretch",
        )

    if submitted:
        try:
            record = api_post(
                "/organization-intelligence/domains",
                {
                    "legal_name": legal_name,
                    "entity_type": entity_type,
                    "domain": domain,
                    "source_name": source_name,
                    "source_type": source_type,
                    "source_record_id": (
                        source_record_id or None
                    ),
                    "source_url": (
                        source_url or None
                    ),
                    "authoritative_source": authoritative,
                    "country_code": (
                        country_code or None
                    ),
                    "jurisdiction": (
                        jurisdiction or None
                    ),
                    "identity_state": identity_state,
                    "security_state": security_state,
                    "identity_confidence": (
                        identity_confidence
                    ),
                    "security_confidence": (
                        security_confidence
                    ),
                },
            )

            st.success(
                "Organization-domain evidence saved."
            )

            st.json(
                record
            )

        except requests.HTTPError as error:
            try:
                detail = error.response.json().get(
                    "detail",
                    str(
                        error
                    ),
                )
            except ValueError:
                detail = str(
                    error
                )

            st.error(
                detail
            )


with import_tab:
    st.write(
        "Place normalized CSV files inside:"
    )

    st.code(
        (
            "data/organization_intelligence/"
            "imports/"
        )
    )

    csv_path = st.text_input(
        "Local CSV path",
        value=(
            "data/organization_intelligence/"
            "imports/organizations.csv"
        ),
    )

    if st.button(
        "Import CSV Dataset",
        width="stretch",
    ):
        try:
            result = api_post(
                "/organization-intelligence/import",
                {
                    "csv_path": csv_path,
                },
            )

            st.success(
                (
                    f"Imported {result['imported']} "
                    f"records; {result['failed']} failed."
                )
            )

            st.json(
                result
            )

        except requests.RequestException as error:
            st.error(
                str(
                    error
                )
            )

    st.warning(
        "Only import domain associations that are "
        "explicitly reported or independently verified. "
        "Do not infer a website solely from an organization name."
    )


with records_tab:
    try:
        records = api_get(
            "/organization-intelligence/domains"
        ).get(
            "domains",
            [],
        )

    except requests.RequestException as error:
        st.error(
            str(
                error
            )
        )

        records = []

    if records:
        st.dataframe(
            pd.DataFrame(
                records
            ),
            width="stretch",
            hide_index=True,
        )

    else:
        st.info(
            "No organization-domain records have "
            "been imported yet."
        )
