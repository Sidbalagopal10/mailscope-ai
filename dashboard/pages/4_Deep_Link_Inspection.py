from __future__ import annotations

import pandas as pd
import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Deep Link Inspection",
    page_icon="🔎",
    layout="wide",
)

st.title("🔎 Safe Deep Link Inspection")

st.caption(
    "Manually inspect redirects, destination domains, page titles, "
    "and login forms without executing JavaScript."
)


url = st.text_input(
    "URL",
    placeholder="https://example.com/",
)

confirmation = st.checkbox(
    "I understand this sends a limited HTTP request "
    "to the submitted public URL."
)

inspect_clicked = st.button(
    "Inspect Link",
    type="primary",
    width="stretch",
)


if inspect_clicked:
    if not url.strip():
        st.warning(
            "Enter a URL before starting the inspection."
        )

    elif not confirmation:
        st.warning(
            "Confirm that you understand a limited HTTP request "
            "will be sent."
        )

    else:
        with st.spinner(
            "Safely inspecting the link..."
        ):
            try:
                response = requests.post(
                    f"{API_BASE_URL}/deep-inspection/inspect",
                    json={
                        "url": url.strip(),
                    },
                    timeout=45,
                )

                response.raise_for_status()

                st.session_state[
                    "deep_inspection_result"
                ] = response.json()

            except requests.ConnectionError:
                st.error(
                    "FastAPI is not running."
                )

            except requests.Timeout:
                st.error(
                    "Inspection timed out."
                )

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
                    f"Inspection failed: {error}"
                )


result = st.session_state.get(
    "deep_inspection_result"
)

if not result:
    st.info(
        "Enter a public HTTP or HTTPS URL to begin."
    )

    st.stop()


metric1, metric2, metric3, metric4 = st.columns(4)

metric1.metric(
    "HTTP Status",
    result.get(
        "status_code",
        "Unknown",
    ),
)

metric2.metric(
    "Redirects",
    result.get(
        "redirect_count",
        0,
    ),
)

metric3.metric(
    "Password Fields",
    result.get(
        "password_input_count",
        0,
    ),
)

metric4.metric(
    "External Password Forms",
    result.get(
        "external_password_form_count",
        0,
    ),
)


st.write("**Page title**")

st.code(
    result.get(
        "page_title"
    )
    or "(No title detected)"
)


st.write("**Final destination**")

st.code(
    result.get(
        "final_url",
        "",
    )
)


findings = result.get(
    "findings",
    [],
)

if findings:
    st.warning(
        "Inspection findings:"
    )

    for finding in findings:
        st.write(
            f"- {finding}"
        )

else:
    st.success(
        "No strong static page-level indicators were detected."
    )


st.subheader(
    "Redirect Chain"
)

redirects = result.get(
    "redirect_chain",
    [],
)

if redirects:
    st.dataframe(
        pd.DataFrame(
            redirects
        ),
        width="stretch",
        hide_index=True,
    )

else:
    st.write(
        "No redirect information was returned."
    )


st.subheader(
    "Form Destinations"
)

forms = result.get(
    "forms",
    [],
)

if forms:
    st.dataframe(
        pd.DataFrame(
            forms
        ),
        width="stretch",
        hide_index=True,
    )

else:
    st.write(
        "No HTML forms were detected."
    )


with st.expander(
    "View complete inspection result"
):
    st.json(
        result
    )


st.warning(
    "This is static inspection only. It does not execute "
    "JavaScript, submit forms, sign in, or download files."
)
