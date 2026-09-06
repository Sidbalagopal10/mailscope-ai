import base64
import re
from html import unescape
from typing import Any

from bs4 import BeautifulSoup


URL_PATTERN = re.compile(
    r'https?://[^\s<>"\'\]\)]+',
    re.IGNORECASE,
)


def decode_body(data: str) -> str:
    if not data:
        return ""

    padding = "=" * (-len(data) % 4)

    try:
        decoded = base64.urlsafe_b64decode(data + padding)
        return decoded.decode("utf-8", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return ""


def collect_message_parts(
    payload: dict[str, Any],
) -> tuple[list[str], list[str]]:
    plain_parts: list[str] = []
    html_parts: list[str] = []

    mime_type = payload.get("mimeType", "")
    body_data = payload.get("body", {}).get("data")

    if body_data:
        content = decode_body(body_data)

        if mime_type == "text/plain":
            plain_parts.append(content)
        elif mime_type == "text/html":
            html_parts.append(content)

    for part in payload.get("parts", []):
        child_plain, child_html = collect_message_parts(part)
        plain_parts.extend(child_plain)
        html_parts.extend(child_html)

    return plain_parts, html_parts


def extract_urls_from_html(html_content: str) -> set[str]:
    urls: set[str] = set()

    soup = BeautifulSoup(html_content, "html.parser")

    for element in soup.find_all(href=True):
        href = unescape(element.get("href", "")).strip()

        if href.startswith(("http://", "https://")):
            urls.add(href)

    visible_text = soup.get_text(" ", strip=True)
    urls.update(URL_PATTERN.findall(visible_text))

    return urls


def extract_urls_from_message(
    payload: dict[str, Any],
) -> list[str]:
    plain_parts, html_parts = collect_message_parts(payload)

    urls: set[str] = set()

    for plain_content in plain_parts:
        urls.update(URL_PATTERN.findall(plain_content))

    for html_content in html_parts:
        urls.update(extract_urls_from_html(html_content))

    return sorted(urls)
