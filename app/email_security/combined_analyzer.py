from __future__ import annotations

import base64
import html
import re
from typing import Any

from bs4 import BeautifulSoup

from app.detection.email_content_analyzer import (
    analyze_email_content,
)
from app.detection.hybrid_detector import (
    analyze_url_hybrid,
)


URL_PATTERN = re.compile(
    r'https?://[^\s<>"\'\]\)]+',
    re.IGNORECASE,
)

TRACKING_DOMAINS = {
    "fonts.googleapis.com",
    "fonts.gstatic.com",
}


def decode_base64url(value: str) -> str:
    if not value:
        return ""

    padding = "=" * (-len(value) % 4)

    try:
        decoded = base64.urlsafe_b64decode(
            value + padding
        )

        return decoded.decode(
            "utf-8",
            errors="replace",
        )

    except (ValueError, TypeError):
        return ""


def collect_message_content(
    payload: dict[str, Any],
) -> tuple[list[str], list[str]]:
    plain_parts: list[str] = []
    html_parts: list[str] = []

    mime_type = payload.get(
        "mimeType",
        "",
    )

    body_data = (
        payload.get(
            "body",
            {},
        ).get(
            "data"
        )
    )

    if body_data:
        content = decode_base64url(
            body_data
        )

        if mime_type == "text/plain":
            plain_parts.append(
                content
            )

        elif mime_type == "text/html":
            html_parts.append(
                content
            )

    for part in payload.get(
        "parts",
        [],
    ):
        child_plain, child_html = (
            collect_message_content(
                part
            )
        )

        plain_parts.extend(
            child_plain
        )

        html_parts.extend(
            child_html
        )

    return plain_parts, html_parts


def extract_text_and_urls(
    payload: dict[str, Any],
) -> tuple[str, list[str]]:
    plain_parts, html_parts = (
        collect_message_content(
            payload
        )
    )

    text_sections: list[str] = []
    urls: set[str] = set()

    for plain_content in plain_parts:
        text_sections.append(
            plain_content
        )

        urls.update(
            URL_PATTERN.findall(
                plain_content
            )
        )

    for html_content in html_parts:
        soup = BeautifulSoup(
            html_content,
            "html.parser",
        )

        visible_text = soup.get_text(
            " ",
            strip=True,
        )

        if visible_text:
            text_sections.append(
                visible_text
            )

        for element in soup.find_all(
            href=True
        ):
            href = html.unescape(
                element.get(
                    "href",
                    "",
                )
            ).strip()

            if href.startswith(
                (
                    "http://",
                    "https://",
                )
            ):
                urls.add(
                    href
                )

        urls.update(
            URL_PATTERN.findall(
                visible_text
            )
        )

    cleaned_urls = []

    for url in sorted(urls):
        if any(
            domain in url.lower()
            for domain in TRACKING_DOMAINS
        ):
            continue

        cleaned_urls.append(
            url
        )

    combined_text = "\n\n".join(
        section.strip()
        for section in text_sections
        if section.strip()
    )

    return (
        combined_text,
        cleaned_urls,
    )


def get_header(
    headers: list[dict[str, Any]],
    name: str,
) -> str:
    for header in headers:
        if (
            header.get(
                "name",
                "",
            ).lower()
            == name.lower()
        ):
            return header.get(
                "value",
                "",
            )

    return ""


def score_to_risk_level(
    score: float,
) -> str:
    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 40:
        return "MODERATE"

    if score >= 20:
        return "GUARDED"

    return "LOW"


def analyze_gmail_message(
    message: dict[str, Any],
) -> dict[str, Any]:
    payload = message.get(
        "payload",
        {},
    )

    headers = payload.get(
        "headers",
        [],
    )

    subject = (
        get_header(
            headers,
            "Subject",
        )
        or "(No subject)"
    )

    sender = (
        get_header(
            headers,
            "From",
        )
        or "(Unknown sender)"
    )

    date = get_header(
        headers,
        "Date",
    )

    body_text, urls = (
        extract_text_and_urls(
            payload
        )
    )

    content_result = (
        analyze_email_content(
            subject=subject,
            body=body_text,
            sender=sender,
        )
    )

    url_results: list[
        dict[str, Any]
    ] = []

    for url in urls:
        try:
            url_results.append(
                analyze_url_hybrid(
                    url
                )
            )

        except Exception as error:
            url_results.append(
                {
                    "url": url,
                    "final_score": 0,
                    "risk_level": "unknown",
                    "is_phishing": False,
                    "error": str(error),
                }
            )

    highest_url_score = max(
        (
            float(
                result.get(
                    "final_score",
                    0,
                )
                or 0
            )
            for result in url_results
        ),
        default=0,
    )

    suspicious_url_count = sum(
        1
        for result in url_results
        if bool(
            result.get(
                "is_suspicious",
                False,
            )
        )
    )

    phishing_url_count = sum(
        1
        for result in url_results
        if bool(
            result.get(
                "is_phishing",
                False,
            )
        )
    )

    content_score = float(
        content_result.get(
            "content_score",
            0,
        )
        or 0
    )

    if url_results:
        combined_score = (
            content_score * 0.40
            + highest_url_score * 0.60
        )

    else:
        combined_score = (
            content_score
        )

    if (
        phishing_url_count > 0
        and content_score >= 40
    ):
        combined_score += 8

    combined_score = round(
        min(
            combined_score,
            100,
        ),
        2,
    )

    risk_level = score_to_risk_level(
        combined_score
    )

    reasons = list(
        content_result.get(
            "reasons",
            [],
        )
    )

    if highest_url_score >= 60:
        reasons.append(
            "At least one URL received a high "
            "phishing-risk score."
        )

    elif highest_url_score >= 40:
        reasons.append(
            "At least one URL contains notable "
            "phishing indicators."
        )

    if (
        content_score >= 40
        and highest_url_score >= 40
    ):
        reasons.append(
            "Suspicious language and suspicious URLs "
            "appear together in the same message."
        )

    if combined_score >= 60:
        recommendation = (
            "Do not click links, open attachments, "
            "send credentials, or reply to this message. "
            "Verify the sender independently."
        )

    elif combined_score >= 40:
        recommendation = (
            "Treat this message cautiously and verify "
            "the sender before taking any action."
        )

    else:
        recommendation = (
            "No strong combined phishing indicators "
            "were found, but normal email caution "
            "is still recommended."
        )

    return {
        "gmail_message_id": message.get(
            "id"
        ),
        "thread_id": message.get(
            "threadId"
        ),
        "subject": subject,
        "sender": sender,
        "date": date,
        "body_length": len(
            body_text
        ),
        "link_count": len(
            urls
        ),
        "suspicious_url_count": (
            suspicious_url_count
        ),
        "phishing_url_count": (
            phishing_url_count
        ),
        "content_score": round(
            content_score,
            2,
        ),
        "highest_url_score": round(
            highest_url_score,
            2,
        ),
        "combined_score": combined_score,
        "risk_level": risk_level,
        "is_suspicious": (
            combined_score >= 40
        ),
        "is_phishing": (
            combined_score >= 60
        ),
        "recommendation": recommendation,
        "reasons": reasons,
        "content_analysis": (
            content_result
        ),
        "url_results": url_results,
    }
