from __future__ import annotations

import hashlib
import io
import ipaddress
import mimetypes
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import cv2
import fitz
import numpy as np
from PIL import Image
from pypdf import PdfReader


MAX_FILE_SIZE = 25 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 250
MAX_ARCHIVE_UNCOMPRESSED_SIZE = 100 * 1024 * 1024
MAX_PDF_PAGES_FOR_QR = 8
MAX_QR_RESULTS = 25
MAX_TEXT_LENGTH = 100_000

URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"\]\)]+",
    re.IGNORECASE,
)

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".msi",
    ".msp",
    ".cpl",
    ".sys",
    ".drv",
    ".app",
    ".dmg",
    ".pkg",
    ".deb",
    ".rpm",
    ".apk",
    ".jar",
}

SCRIPT_EXTENSIONS = {
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".wsf",
    ".wsh",
    ".ps1",
    ".psm1",
    ".bat",
    ".cmd",
    ".hta",
    ".sh",
    ".bash",
    ".zsh",
    ".py",
    ".pl",
    ".rb",
}

MACRO_OFFICE_EXTENSIONS = {
    ".docm",
    ".dotm",
    ".xlsm",
    ".xltm",
    ".xlam",
    ".pptm",
    ".potm",
    ".ppam",
    ".ppsm",
    ".sldm",
}

LEGACY_OFFICE_EXTENSIONS = {
    ".doc",
    ".xls",
    ".ppt",
}

ARCHIVE_EXTENSIONS = {
    ".zip",
    ".jar",
    ".docx",
    ".xlsx",
    ".pptx",
    ".docm",
    ".xlsm",
    ".pptm",
}

IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".bmp",
    ".gif",
    ".tif",
    ".tiff",
    ".webp",
}

SUSPICIOUS_ARCHIVE_MEMBER_EXTENSIONS = (
    EXECUTABLE_EXTENSIONS
    | SCRIPT_EXTENSIONS
    | MACRO_OFFICE_EXTENSIONS
)

DANGEROUS_PDF_MARKERS = {
    "/JavaScript",
    "/JS",
    "/Launch",
    "/EmbeddedFile",
    "/OpenAction",
    "/AA",
    "/RichMedia",
    "/SubmitForm",
    "/ImportData",
}

SUSPICIOUS_FILENAME_TERMS = {
    "invoice",
    "payment",
    "payroll",
    "refund",
    "password",
    "credential",
    "verify",
    "secure",
    "urgent",
    "statement",
    "bank",
    "remittance",
    "purchase-order",
}


class AttachmentInspectionError(Exception):
    pass


def clamp(
    value: float,
    minimum: float = 0.0,
    maximum: float = 100.0,
) -> float:
    return max(
        minimum,
        min(
            float(value),
            maximum,
        ),
    )


def risk_level_for_score(
    score: float,
) -> str:
    if score >= 80:
        return "critical"

    if score >= 60:
        return "high"

    if score >= 35:
        return "moderate"

    return "low"


def classification_for_score(
    score: float,
) -> str:
    if score >= 80:
        return "likely_malicious_attachment"

    if score >= 60:
        return "high_risk_attachment"

    if score >= 35:
        return "attachment_needs_review"

    return "likely_benign_attachment"


def sha256_bytes(
    data: bytes,
) -> str:
    return hashlib.sha256(
        data
    ).hexdigest()


def normalized_suffixes(
    filename: str,
) -> list[str]:
    return [
        suffix.lower()
        for suffix in Path(
            filename
        ).suffixes
    ]


def final_extension(
    filename: str,
) -> str:
    suffixes = normalized_suffixes(
        filename
    )

    return (
        suffixes[-1]
        if suffixes
        else ""
    )


def detect_double_extension(
    filename: str,
) -> dict[str, Any]:
    suffixes = normalized_suffixes(
        filename
    )

    if len(
        suffixes
    ) < 2:
        return {
            "detected": False,
            "suffixes": suffixes,
            "dangerous_final_extension": False,
        }

    dangerous_final = bool(
        suffixes[-1]
        in (
            EXECUTABLE_EXTENSIONS
            | SCRIPT_EXTENSIONS
        )
    )

    misleading_prior = bool(
        suffixes[-2]
        in {
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".ppt",
            ".pptx",
            ".jpg",
            ".jpeg",
            ".png",
            ".txt",
        }
    )

    return {
        "detected": bool(
            dangerous_final
            and misleading_prior
        ),
        "suffixes": suffixes,
        "dangerous_final_extension": dangerous_final,
        "misleading_prior_extension": misleading_prior,
    }


def infer_mime_type(
    filename: str,
) -> str:
    mime_type, _ = mimetypes.guess_type(
        filename
    )

    return (
        mime_type
        or "application/octet-stream"
    )


def extract_urls_from_text(
    text: str,
) -> list[str]:
    urls: list[str] = []

    for match in URL_PATTERN.findall(
        text or ""
    ):
        cleaned = match.rstrip(
            ".,;:!?]})>'\""
        )

        if cleaned not in urls:
            urls.append(
                cleaned
            )

    return urls


def url_basic_risk(
    url: str,
) -> dict[str, Any]:
    score = 0.0
    reasons: list[str] = []

    lowered = str(
        url or ""
    ).lower()

    try:
        parsed = urlsplit(
            url
        )

    except ValueError:
        return {
            "url": url,
            "risk_score": 20.0,
            "reasons": [
                "The decoded URL could not be parsed normally."
            ],
        }

    hostname = (
        parsed.hostname
        or ""
    ).lower()

    if parsed.scheme == "http":
        score = max(
            score,
            15.0,
        )

        reasons.append(
            "The URL uses unencrypted HTTP."
        )

    try:
        ipaddress.ip_address(
            hostname
        )

        score = max(
            score,
            70.0,
        )

        reasons.append(
            "The URL uses a raw IP address."
        )

    except ValueError:
        pass

    suspicious_terms = {
        "login",
        "verify",
        "password",
        "credential",
        "secure",
        "account-update",
        "payment",
        "wallet",
        "gift-card",
        "refund",
        "bank",
    }

    matched_terms = sorted(
        term
        for term in suspicious_terms
        if term in lowered
    )

    if matched_terms:
        score = max(
            score,
            35.0,
        )

        reasons.append(
            "The URL contains sensitive-action wording: "
            + ", ".join(
                matched_terms
            )
        )

    if "@" in parsed.netloc:
        score = max(
            score,
            65.0,
        )

        reasons.append(
            "The URL authority contains an @ character."
        )

    if len(
        url
    ) > 200:
        score = max(
            score,
            20.0,
        )

        reasons.append(
            "The URL is unusually long."
        )

    return {
        "url": url,
        "risk_score": round(
            score,
            2,
        ),
        "reasons": reasons,
    }


def decode_qr_from_image_array(
    image_array: np.ndarray,
) -> list[str]:
    detector = cv2.QRCodeDetector()

    decoded_values: list[str] = []

    try:
        (
            detected,
            decoded_info,
            _,
            _,
        ) = detector.detectAndDecodeMulti(
            image_array
        )

        if detected:
            for value in decoded_info:
                cleaned = str(
                    value or ""
                ).strip()

                if (
                    cleaned
                    and cleaned
                    not in decoded_values
                ):
                    decoded_values.append(
                        cleaned
                    )

    except cv2.error:
        pass

    if not decoded_values:
        try:
            value, _, _ = detector.detectAndDecode(
                image_array
            )

            cleaned = str(
                value or ""
            ).strip()

            if cleaned:
                decoded_values.append(
                    cleaned
                )

        except cv2.error:
            pass

    return decoded_values[
        :MAX_QR_RESULTS
    ]


def decode_qr_from_image_bytes(
    data: bytes,
) -> list[str]:
    try:
        image = Image.open(
            io.BytesIO(
                data
            )
        ).convert(
            "RGB"
        )

    except Exception:
        return []

    image_array = np.asarray(
        image
    )

    bgr = cv2.cvtColor(
        image_array,
        cv2.COLOR_RGB2BGR,
    )

    return decode_qr_from_image_array(
        bgr
    )


def inspect_archive(
    data: bytes,
) -> dict[str, Any]:
    result = {
        "is_archive": False,
        "encrypted": False,
        "member_count": 0,
        "total_uncompressed_size": 0,
        "suspicious_members": [],
        "nested_archives": [],
        "path_traversal_members": [],
        "limit_exceeded": False,
        "error": None,
    }

    try:
        archive = zipfile.ZipFile(
            io.BytesIO(
                data
            )
        )

    except (
        zipfile.BadZipFile,
        OSError,
    ):
        return result

    result[
        "is_archive"
    ] = True

    try:
        members = archive.infolist()

        result[
            "member_count"
        ] = len(
            members
        )

        if len(
            members
        ) > MAX_ARCHIVE_MEMBERS:
            result[
                "limit_exceeded"
            ] = True

        total_size = 0

        for member in members[
            :MAX_ARCHIVE_MEMBERS
        ]:
            total_size += int(
                member.file_size
            )

            member_name = str(
                member.filename
            )

            member_path = Path(
                member_name
            )

            if (
                member_name.startswith(
                    (
                        "/",
                        "\\",
                    )
                )
                or ".."
                in member_path.parts
            ):
                result[
                    "path_traversal_members"
                ].append(
                    member_name
                )

            member_extension = (
                member_path.suffix.lower()
            )

            if (
                member_extension
                in SUSPICIOUS_ARCHIVE_MEMBER_EXTENSIONS
            ):
                result[
                    "suspicious_members"
                ].append(
                    member_name
                )

            if (
                member_extension
                in ARCHIVE_EXTENSIONS
            ):
                result[
                    "nested_archives"
                ].append(
                    member_name
                )

            if member.flag_bits & 0x1:
                result[
                    "encrypted"
                ] = True

        result[
            "total_uncompressed_size"
        ] = total_size

        if (
            total_size
            > MAX_ARCHIVE_UNCOMPRESSED_SIZE
        ):
            result[
                "limit_exceeded"
            ] = True

    except Exception as error:
        result[
            "error"
        ] = str(
            error
        )

    finally:
        archive.close()

    return result


def inspect_pdf(
    data: bytes,
) -> dict[str, Any]:
    result = {
        "is_pdf": False,
        "encrypted": False,
        "page_count": 0,
        "dangerous_markers": [],
        "embedded_file_detected": False,
        "javascript_detected": False,
        "open_action_detected": False,
        "extracted_urls": [],
        "qr_values": [],
        "text_length": 0,
        "error": None,
    }

    if not data.startswith(
        b"%PDF"
    ):
        return result

    result[
        "is_pdf"
    ] = True

    raw_text = data.decode(
        "latin-1",
        errors="ignore",
    )

    markers = sorted(
        marker
        for marker in DANGEROUS_PDF_MARKERS
        if marker in raw_text
    )

    result[
        "dangerous_markers"
    ] = markers

    result[
        "embedded_file_detected"
    ] = "/EmbeddedFile" in markers

    result[
        "javascript_detected"
    ] = bool(
        {
            "/JavaScript",
            "/JS",
        }
        & set(
            markers
        )
    )

    result[
        "open_action_detected"
    ] = "/OpenAction" in markers

    extracted_text: list[str] = []

    try:
        reader = PdfReader(
            io.BytesIO(
                data
            )
        )

        result[
            "encrypted"
        ] = bool(
            reader.is_encrypted
        )

        if not reader.is_encrypted:
            result[
                "page_count"
            ] = len(
                reader.pages
            )

            for page in reader.pages:
                try:
                    text = page.extract_text(
                    extraction_mode="plain"
                )

                except TypeError:
                    text = page.extract_text()

                except Exception:
                    text = ""

                if text:
                    extracted_text.append(
                        text
                    )

                if sum(
                    len(
                        value
                    )
                    for value in extracted_text
                ) >= MAX_TEXT_LENGTH:
                    break

    except Exception as error:
        result[
            "error"
        ] = str(
            error
        )

    combined_text = "\n".join(
        extracted_text
    )[
        :MAX_TEXT_LENGTH
    ]

    result[
        "text_length"
    ] = len(
        combined_text
    )

    result[
        "extracted_urls"
    ] = extract_urls_from_text(
        combined_text
    )

    try:
        document = fitz.open(
            stream=data,
            filetype="pdf",
        )

        result[
            "page_count"
        ] = max(
            result[
                "page_count"
            ],
            document.page_count,
        )

        qr_values: list[str] = []

        for page_number in range(
            min(
                document.page_count,
                MAX_PDF_PAGES_FOR_QR,
            )
        ):
            page = document.load_page(
                page_number
            )

            pixmap = page.get_pixmap(
                matrix=fitz.Matrix(
                    1.8,
                    1.8,
                ),
                alpha=False,
            )

            image_array = np.frombuffer(
                pixmap.samples,
                dtype=np.uint8,
            ).reshape(
                pixmap.height,
                pixmap.width,
                pixmap.n,
            )

            if pixmap.n == 4:
                image_array = cv2.cvtColor(
                    image_array,
                    cv2.COLOR_RGBA2BGR,
                )

            else:
                image_array = cv2.cvtColor(
                    image_array,
                    cv2.COLOR_RGB2BGR,
                )

            for value in decode_qr_from_image_array(
                image_array
            ):
                if value not in qr_values:
                    qr_values.append(
                        value
                    )

            if len(
                qr_values
            ) >= MAX_QR_RESULTS:
                break

        result[
            "qr_values"
        ] = qr_values[
            :MAX_QR_RESULTS
        ]

        document.close()

    except Exception:
        pass

    return result


def inspect_office_archive(
    data: bytes,
    filename: str,
) -> dict[str, Any]:
    result = {
        "is_office_archive": False,
        "macro_container_detected": False,
        "external_relationships": [],
        "embedded_objects": [],
        "error": None,
    }

    extension = final_extension(
        filename
    )

    if extension not in ARCHIVE_EXTENSIONS:
        return result

    try:
        archive = zipfile.ZipFile(
            io.BytesIO(
                data
            )
        )

    except zipfile.BadZipFile:
        return result

    result[
        "is_office_archive"
    ] = extension in {
        ".docx",
        ".xlsx",
        ".pptx",
        ".docm",
        ".xlsm",
        ".pptm",
    }

    try:
        for member in archive.namelist():
            lowered = member.lower()

            if lowered.endswith(
                "vbaproject.bin"
            ):
                result[
                    "macro_container_detected"
                ] = True

            if (
                "/embeddings/"
                in lowered
                or lowered.startswith(
                    "embeddings/"
                )
            ):
                result[
                    "embedded_objects"
                ].append(
                    member
                )

            if lowered.endswith(
                ".rels"
            ):
                try:
                    content = archive.read(
                        member
                    ).decode(
                        "utf-8",
                        errors="ignore",
                    )

                except Exception:
                    continue

                external_targets = re.findall(
                    r'Target="([^"]+)"[^>]*TargetMode="External"',
                    content,
                    flags=re.IGNORECASE,
                )

                for target in external_targets:
                    if (
                        target
                        not in result[
                            "external_relationships"
                        ]
                    ):
                        result[
                            "external_relationships"
                        ].append(
                            target
                        )

    except Exception as error:
        result[
            "error"
        ] = str(
            error
        )

    finally:
        archive.close()

    return result


def score_attachment(
    *,
    filename: str,
    extension: str,
    file_size: int,
    double_extension: dict[str, Any],
    archive: dict[str, Any],
    pdf: dict[str, Any],
    office: dict[str, Any],
    qr_values: list[str],
) -> dict[str, Any]:
    score = 0.0

    suspicious_signals: list[str] = []
    positive_signals: list[str] = []
    reasons: list[str] = []

    if extension in EXECUTABLE_EXTENSIONS:
        score = max(
            score,
            90.0,
        )

        suspicious_signals.append(
            "The attachment uses an executable or installer format."
        )

    if extension in SCRIPT_EXTENSIONS:
        score = max(
            score,
            82.0,
        )

        suspicious_signals.append(
            "The attachment uses a script format that could execute commands."
        )

    if extension in MACRO_OFFICE_EXTENSIONS:
        score = max(
            score,
            55.0,
        )

        suspicious_signals.append(
            "The attachment uses a macro-enabled Microsoft Office format."
        )

    if extension in LEGACY_OFFICE_EXTENSIONS:
        score = max(
            score,
            20.0,
        )

        suspicious_signals.append(
            "The attachment uses a legacy Office format that requires review."
        )

    if double_extension.get(
        "detected"
    ):
        score = max(
            score,
            92.0,
        )

        suspicious_signals.append(
            "The filename uses a misleading double extension."
        )

    if archive.get(
        "encrypted"
    ):
        score = max(
            score,
            45.0,
        )

        suspicious_signals.append(
            "The archive is encrypted, preventing normal content inspection."
        )

    if archive.get(
        "suspicious_members"
    ):
        score = max(
            score,
            80.0,
        )

        suspicious_signals.append(
            "The archive contains executable, script, or macro-enabled files."
        )

    if archive.get(
        "path_traversal_members"
    ):
        score = max(
            score,
            90.0,
        )

        suspicious_signals.append(
            "The archive contains path-traversal filenames."
        )

    if archive.get(
        "limit_exceeded"
    ):
        score = max(
            score,
            35.0,
        )

        suspicious_signals.append(
            "The archive exceeds safe inspection limits."
        )

    if office.get(
        "macro_container_detected"
    ):
        score = max(
            score,
            65.0,
        )

        suspicious_signals.append(
            "A VBA macro project was found inside the Office document."
        )

    if office.get(
        "embedded_objects"
    ):
        score = max(
            score,
            40.0,
        )

        suspicious_signals.append(
            "The Office document contains embedded objects."
        )

    if office.get(
        "external_relationships"
    ):
        score = max(
            score,
            35.0,
        )

        suspicious_signals.append(
            "The Office document contains external relationships."
        )

    if pdf.get(
        "javascript_detected"
    ):
        score = max(
            score,
            75.0,
        )

        suspicious_signals.append(
            "The PDF contains JavaScript-related objects."
        )

    if pdf.get(
        "embedded_file_detected"
    ):
        score = max(
            score,
            65.0,
        )

        suspicious_signals.append(
            "The PDF contains an embedded file."
        )

    if pdf.get(
        "open_action_detected"
    ):
        score = max(
            score,
            55.0,
        )

        suspicious_signals.append(
            "The PDF contains an automatic open action."
        )

    if pdf.get(
        "encrypted"
    ):
        score = max(
            score,
            25.0,
        )

        suspicious_signals.append(
            "The PDF is encrypted and could not be fully inspected."
        )

    qr_url_results = [
        url_basic_risk(
            value
        )
        for value in qr_values
        if str(
            value
        ).lower().startswith(
            (
                "http://",
                "https://",
            )
        )
    ]

    highest_qr_score = max(
        (
            float(
                result[
                    "risk_score"
                ]
            )
            for result in qr_url_results
        ),
        default=0.0,
    )

    if qr_values:
        score = max(
            score,
            15.0,
        )

        reasons.append(
            f"{len(qr_values)} QR-code value(s) were decoded."
        )

    if highest_qr_score >= 70:
        score = max(
            score,
            80.0,
        )

        suspicious_signals.append(
            "A QR code points to a high-risk URL."
        )

    elif highest_qr_score >= 35:
        score = max(
            score,
            50.0,
        )

        suspicious_signals.append(
            "A QR code points to a URL requiring deeper review."
        )

    filename_lower = filename.lower()

    filename_terms = sorted(
        term
        for term in SUSPICIOUS_FILENAME_TERMS
        if term in filename_lower
    )

    if (
        filename_terms
        and (
            extension
            in (
                EXECUTABLE_EXTENSIONS
                | SCRIPT_EXTENSIONS
                | MACRO_OFFICE_EXTENSIONS
            )
            or double_extension.get(
                "detected"
            )
        )
    ):
        score = max(
            score,
            85.0,
        )

        suspicious_signals.append(
            "The filename combines a financial or security lure "
            "with a dangerous attachment type."
        )

    if file_size == 0:
        reasons.append(
            "The attachment is empty."
        )

    elif (
        score == 0
        and extension
        in {
            ".txt",
            ".csv",
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
        }
    ):
        positive_signals.append(
            "No executable, macro, archive, or active-content indicators "
            "were detected in the attachment format."
        )

    return {
        "risk_score": round(
            clamp(
                score
            ),
            2,
        ),
        "risk_level": risk_level_for_score(
            score
        ),
        "classification": (
            classification_for_score(
                score
            )
        ),
        "is_high_risk": bool(
            score >= 60
        ),
        "suspicious_signals": (
            suspicious_signals
        ),
        "positive_signals": positive_signals,
        "reasons": reasons,
        "qr_url_results": qr_url_results,
        "highest_qr_url_score": round(
            highest_qr_score,
            2,
        ),
    }


def inspect_attachment_bytes(
    *,
    filename: str,
    data: bytes,
    declared_mime_type: str | None = None,
) -> dict[str, Any]:
    safe_filename = Path(
        filename or "attachment.bin"
    ).name

    if len(
        data
    ) > MAX_FILE_SIZE:
        raise AttachmentInspectionError(
            f"Attachment exceeds the {MAX_FILE_SIZE // (1024 * 1024)} MB "
            "inspection limit."
        )

    extension = final_extension(
        safe_filename
    )

    inferred_mime = infer_mime_type(
        safe_filename
    )

    double_extension = detect_double_extension(
        safe_filename
    )

    archive = inspect_archive(
        data
    )

    pdf = inspect_pdf(
        data
    )

    office = inspect_office_archive(
        data,
        safe_filename,
    )

    qr_values: list[str] = []

    if extension in IMAGE_EXTENSIONS:
        qr_values.extend(
            decode_qr_from_image_bytes(
                data
            )
        )

    for value in pdf.get(
        "qr_values",
        [],
    ):
        if value not in qr_values:
            qr_values.append(
                value
            )

    embedded_urls = list(
        pdf.get(
            "extracted_urls",
            [],
        )
    )

    for value in qr_values:
        if (
            value.lower().startswith(
                (
                    "http://",
                    "https://",
                )
            )
            and value not in embedded_urls
        ):
            embedded_urls.append(
                value
            )

    score = score_attachment(
        filename=safe_filename,
        extension=extension,
        file_size=len(
            data
        ),
        double_extension=(
            double_extension
        ),
        archive=archive,
        pdf=pdf,
        office=office,
        qr_values=qr_values,
    )

    return {
        "inspection_version": "1.0.0",
        "analysis_only": True,
        "attachment_executed": False,
        "archive_extracted_to_disk": False,
        "filename": safe_filename,
        "extension": extension,
        "declared_mime_type": (
            declared_mime_type
        ),
        "inferred_mime_type": (
            inferred_mime
        ),
        "size_bytes": len(
            data
        ),
        "sha256": sha256_bytes(
            data
        ),
        "double_extension": (
            double_extension
        ),
        "archive_analysis": archive,
        "pdf_analysis": pdf,
        "office_analysis": office,
        "qr_values": qr_values,
        "embedded_urls": embedded_urls,
        **score,
        "important_limitations": [
            (
                "Static inspection cannot prove that an attachment is safe."
            ),
            (
                "Encrypted files cannot be fully inspected without a password."
            ),
            (
                "This module does not execute, detonate, or sandbox attachments."
            ),
            (
                "QR-code decoding can fail on damaged, low-resolution, "
                "or visually distorted codes."
            ),
            (
                "Macro presence increases risk but does not by itself prove "
                "malicious behavior."
            ),
        ],
    }


def inspect_attachment_path(
    path: Path,
    *,
    declared_mime_type: str | None = None,
) -> dict[str, Any]:
    if not path.exists():
        raise AttachmentInspectionError(
            f"Attachment does not exist: {path}"
        )

    if not path.is_file():
        raise AttachmentInspectionError(
            "Attachment path is not a regular file."
        )

    return inspect_attachment_bytes(
        filename=path.name,
        data=path.read_bytes(),
        declared_mime_type=(
            declared_mime_type
        ),
    )
