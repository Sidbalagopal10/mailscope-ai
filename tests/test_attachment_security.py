from __future__ import annotations

import io
import zipfile

from app.attachment_security.inspector import (
    detect_double_extension,
    inspect_attachment_bytes,
    url_basic_risk,
)


def make_zip(
    members: dict[str, bytes],
) -> bytes:
    buffer = io.BytesIO()

    with zipfile.ZipFile(
        buffer,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        for name, data in members.items():
            archive.writestr(
                name,
                data,
            )

    return buffer.getvalue()


def test_plain_text_is_low_risk():
    result = inspect_attachment_bytes(
        filename="notes.txt",
        data=b"Normal meeting notes.",
        declared_mime_type="text/plain",
    )

    assert result[
        "risk_level"
    ] == "low"

    assert not result[
        "attachment_executed"
    ]


def test_executable_is_critical():
    result = inspect_attachment_bytes(
        filename="invoice.exe",
        data=b"MZ" + b"\x00" * 100,
    )

    assert result[
        "risk_score"
    ] >= 90

    assert result[
        "risk_level"
    ] == "critical"


def test_double_extension_is_critical():
    detected = detect_double_extension(
        "invoice.pdf.exe"
    )

    assert detected[
        "detected"
    ]

    result = inspect_attachment_bytes(
        filename="invoice.pdf.exe",
        data=b"MZ" + b"\x00" * 100,
    )

    assert result[
        "risk_score"
    ] >= 92


def test_macro_extension_is_moderate_or_high():
    result = inspect_attachment_bytes(
        filename="invoice.docm",
        data=make_zip(
            {
                "word/document.xml": b"<document/>",
                "word/vbaProject.bin": b"macro",
            }
        ),
    )

    assert result[
        "risk_score"
    ] >= 65

    assert result[
        "office_analysis"
    ][
        "macro_container_detected"
    ]


def test_archive_with_script_is_high():
    result = inspect_attachment_bytes(
        filename="documents.zip",
        data=make_zip(
            {
                "readme.txt": b"hello",
                "update.js": b"alert('x')",
            }
        ),
    )

    assert result[
        "risk_score"
    ] >= 80

    assert (
        "update.js"
        in result[
            "archive_analysis"
        ][
            "suspicious_members"
        ]
    )


def test_archive_path_traversal_is_critical():
    result = inspect_attachment_bytes(
        filename="archive.zip",
        data=make_zip(
            {
                "../../payload.sh": b"echo bad",
            }
        ),
    )

    assert result[
        "risk_score"
    ] >= 90

    assert result[
        "archive_analysis"
    ][
        "path_traversal_members"
    ]


def test_pdf_javascript_marker_is_high():
    fake_pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /OpenAction 2 0 R /JavaScript /JS >>\n"
        b"endobj\n"
        b"%%EOF"
    )

    result = inspect_attachment_bytes(
        filename="document.pdf",
        data=fake_pdf,
    )

    assert result[
        "risk_score"
    ] >= 75

    assert result[
        "pdf_analysis"
    ][
        "javascript_detected"
    ]


def test_raw_ip_qr_url_risk():
    result = url_basic_risk(
        "http://192.0.2.10/verify-password"
    )

    assert result[
        "risk_score"
    ] >= 70


def test_normal_https_qr_url_is_low():
    result = url_basic_risk(
        "https://example.edu/course"
    )

    assert result[
        "risk_score"
    ] < 35


def test_attachment_result_is_analysis_only():
    result = inspect_attachment_bytes(
        filename="image.png",
        data=b"not-a-real-image",
    )

    assert result[
        "analysis_only"
    ]

    assert not result[
        "attachment_executed"
    ]

    assert not result[
        "archive_extracted_to_disk"
    ]
