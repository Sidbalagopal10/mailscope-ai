from __future__ import annotations

import requests
import streamlit as st


API_BASE_URL = "http://127.0.0.1:8000"


st.set_page_config(
    page_title="Attachment and QR Inspection",
    page_icon="📎",
    layout="wide",
)

st.title(
    "📎 Attachment and QR-Code Inspection"
)

st.caption(
    "Static, non-executing inspection of email attachments, "
    "archives, PDFs, Office documents, images, and QR codes."
)

st.warning(
    "Static inspection cannot prove that a file is safe. "
    "The attachment is not executed or detonated."
)


uploaded_file = st.file_uploader(
    "Choose an attachment",
    type=None,
)


if uploaded_file is not None:
    st.write(
        f"**Filename:** {uploaded_file.name}"
    )

    st.write(
        f"**Size:** {uploaded_file.size:,} bytes"
    )

    if st.button(
        "Inspect Attachment",
        type="primary",
        width="stretch",
    ):
        try:
            with st.spinner(
                "Inspecting metadata, archive contents, PDF objects, "
                "Office structures, URLs, and QR codes..."
            ):
                response = requests.post(
                    (
                        f"{API_BASE_URL}"
                        "/attachment-security/inspect"
                    ),
                    files={
                        "file": (
                            uploaded_file.name,
                            uploaded_file.getvalue(),
                            uploaded_file.type
                            or "application/octet-stream",
                        )
                    },
                    timeout=300,
                )

            response.raise_for_status()

            result = response.json()

            metric1, metric2, metric3, metric4 = st.columns(
                4
            )

            metric1.metric(
                "Risk Score",
                result.get(
                    "risk_score",
                    0,
                ),
            )

            metric2.metric(
                "Risk Level",
                str(
                    result.get(
                        "risk_level",
                        "unknown",
                    )
                ).upper(),
            )

            metric3.metric(
                "QR Values",
                len(
                    result.get(
                        "qr_values",
                        [],
                    )
                ),
            )

            metric4.metric(
                "Embedded URLs",
                len(
                    result.get(
                        "embedded_urls",
                        [],
                    )
                ),
            )

            risk_level = result.get(
                "risk_level"
            )

            if risk_level in {
                "high",
                "critical",
            }:
                st.error(
                    result.get(
                        "classification"
                    )
                )

            elif risk_level == "moderate":
                st.warning(
                    result.get(
                        "classification"
                    )
                )

            else:
                st.success(
                    result.get(
                        "classification"
                    )
                )

            tab1, tab2, tab3, tab4, tab5 = st.tabs(
                [
                    "Verdict",
                    "File Metadata",
                    "Archive and Office",
                    "PDF and QR",
                    "Complete Result",
                ]
            )

            with tab1:
                st.json(
                    {
                        "risk_score": result.get(
                            "risk_score"
                        ),
                        "risk_level": result.get(
                            "risk_level"
                        ),
                        "classification": result.get(
                            "classification"
                        ),
                        "suspicious_signals": result.get(
                            "suspicious_signals"
                        ),
                        "positive_signals": result.get(
                            "positive_signals"
                        ),
                        "reasons": result.get(
                            "reasons"
                        ),
                    }
                )

            with tab2:
                st.json(
                    {
                        "filename": result.get(
                            "filename"
                        ),
                        "extension": result.get(
                            "extension"
                        ),
                        "declared_mime_type": result.get(
                            "declared_mime_type"
                        ),
                        "inferred_mime_type": result.get(
                            "inferred_mime_type"
                        ),
                        "size_bytes": result.get(
                            "size_bytes"
                        ),
                        "sha256": result.get(
                            "sha256"
                        ),
                        "double_extension": result.get(
                            "double_extension"
                        ),
                    }
                )

            with tab3:
                st.subheader(
                    "Archive Analysis"
                )

                st.json(
                    result.get(
                        "archive_analysis"
                    )
                )

                st.subheader(
                    "Office Analysis"
                )

                st.json(
                    result.get(
                        "office_analysis"
                    )
                )

            with tab4:
                st.subheader(
                    "PDF Analysis"
                )

                st.json(
                    result.get(
                        "pdf_analysis"
                    )
                )

                st.subheader(
                    "Decoded QR Values"
                )

                qr_values = result.get(
                    "qr_values",
                    [],
                )

                if qr_values:
                    for value in qr_values:
                        st.code(
                            value
                        )

                else:
                    st.info(
                        "No QR-code values were decoded."
                    )

                st.subheader(
                    "QR URL Risk"
                )

                st.json(
                    result.get(
                        "qr_url_results"
                    )
                )

            with tab5:
                st.json(
                    result
                )

            st.code(
                "analysis_only: true\n"
                "attachment_executed: false\n"
                "archive_extracted_to_disk: false"
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

        except requests.RequestException as error:
            st.error(
                str(
                    error
                )
            )
