from __future__ import annotations

import ipaddress
import re
import socket
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from app.detection.brand_intelligence import (
    registered_domain_approximation,
)


MAX_REDIRECTS = 5
MAX_HTML_BYTES = 500_000
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 10

ALLOWED_SCHEMES = {
    "http",
    "https",
}

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
}


class DeepInspectionError(Exception):
    pass


class PageMetadataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()

        self.in_title = False
        self.title_parts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.current_form: dict[str, Any] | None = None
        self.password_input_count = 0

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attributes = {
            key.lower(): value or ""
            for key, value in attrs
        }

        tag = tag.lower()

        if tag == "title":
            self.in_title = True

        elif tag == "form":
            self.current_form = {
                "action": attributes.get("action", ""),
                "method": attributes.get(
                    "method",
                    "get",
                ).lower(),
                "has_password": False,
            }

            self.forms.append(
                self.current_form
            )

        elif tag == "input":
            input_type = attributes.get(
                "type",
                "text",
            ).lower()

            if input_type == "password":
                self.password_input_count += 1

                if self.current_form is not None:
                    self.current_form[
                        "has_password"
                    ] = True

    def handle_endtag(
        self,
        tag: str,
    ) -> None:
        tag = tag.lower()

        if tag == "title":
            self.in_title = False

        elif tag == "form":
            self.current_form = None

    def handle_data(
        self,
        data: str,
    ) -> None:
        if self.in_title:
            self.title_parts.append(
                data.strip()
            )

    @property
    def title(self) -> str:
        title = " ".join(
            part
            for part in self.title_parts
            if part
        )

        return re.sub(
            r"\s+",
            " ",
            title,
        )[:300]


def is_blocked_ip(
    ip_value: str,
) -> bool:
    address = ipaddress.ip_address(
        ip_value
    )

    return any(
        (
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
            not address.is_global,
        )
    )


def resolve_and_validate_hostname(
    hostname: str,
) -> list[str]:
    normalized = str(
        hostname or ""
    ).strip().lower().rstrip(".")

    if not normalized:
        raise DeepInspectionError(
            "The URL does not contain a hostname."
        )

    if normalized in BLOCKED_HOSTNAMES:
        raise DeepInspectionError(
            "Local or internal hostnames are blocked."
        )

    try:
        direct_ip = ipaddress.ip_address(
            normalized
        )

        addresses = [
            str(direct_ip)
        ]

    except ValueError:
        try:
            address_records = socket.getaddrinfo(
                normalized,
                None,
                type=socket.SOCK_STREAM,
            )

        except socket.gaierror as error:
            raise DeepInspectionError(
                "The hostname could not be resolved."
            ) from error

        addresses = sorted(
            {
                record[4][0]
                for record in address_records
            }
        )

    if not addresses:
        raise DeepInspectionError(
            "The hostname did not resolve to an address."
        )

    for address in addresses:
        if is_blocked_ip(
            address
        ):
            raise DeepInspectionError(
                "The destination resolves to a blocked "
                "or non-public IP address."
            )

    return addresses


def validate_url(
    url: str,
) -> dict[str, Any]:
    cleaned = str(
        url or ""
    ).strip()

    parsed = urlparse(
        cleaned
    )

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise DeepInspectionError(
            "Only HTTP and HTTPS URLs are allowed."
        )

    if parsed.username or parsed.password:
        raise DeepInspectionError(
            "URLs containing embedded credentials are blocked."
        )

    if not parsed.hostname:
        raise DeepInspectionError(
            "The URL does not contain a valid hostname."
        )

    addresses = resolve_and_validate_hostname(
        parsed.hostname
    )

    return {
        "url": cleaned,
        "scheme": parsed.scheme.lower(),
        "hostname": parsed.hostname.lower(),
        "port": parsed.port,
        "resolved_addresses": addresses,
    }


def read_limited_response(
    response: requests.Response,
) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    truncated = False

    for chunk in response.iter_content(
        chunk_size=16_384,
    ):
        if not chunk:
            continue

        remaining = (
            MAX_HTML_BYTES - total
        )

        if remaining <= 0:
            truncated = True
            break

        if len(chunk) > remaining:
            chunks.append(
                chunk[:remaining]
            )

            truncated = True
            break

        chunks.append(
            chunk
        )

        total += len(chunk)

    return (
        b"".join(chunks),
        truncated,
    )


def external_form_findings(
    *,
    page_url: str,
    forms: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    page_domain = (
        registered_domain_approximation(
            urlparse(
                page_url
            ).hostname or ""
        )
    )

    findings = []

    for form in forms:
        raw_action = str(
            form.get(
                "action",
                "",
            )
        ).strip()

        resolved_action = urljoin(
            page_url,
            raw_action or page_url,
        )

        action_host = (
            urlparse(
                resolved_action
            ).hostname or ""
        )

        action_domain = (
            registered_domain_approximation(
                action_host
            )
        )

        external = bool(
            page_domain
            and action_domain
            and page_domain != action_domain
        )

        findings.append(
            {
                **form,
                "resolved_action": resolved_action,
                "action_domain": action_domain,
                "external_destination": external,
            }
        )

    return findings


def inspect_url(
    url: str,
) -> dict[str, Any]:
    current_url = validate_url(
        url
    )["url"]

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": (
                "AI-Mail-Phishing-Detector/"
                "Safe-Link-Inspector"
            ),
            "Accept": (
                "text/html,application/xhtml+xml"
            ),
        }
    )

    redirects: list[dict[str, Any]] = []
    response: requests.Response | None = None

    for redirect_number in range(
        MAX_REDIRECTS + 1
    ):
        validated = validate_url(
            current_url
        )

        response = session.get(
            current_url,
            allow_redirects=False,
            stream=True,
            timeout=(
                CONNECT_TIMEOUT,
                READ_TIMEOUT,
            ),
        )

        status_code = int(
            response.status_code
        )

        location = response.headers.get(
            "Location"
        )

        redirects.append(
            {
                "step": redirect_number,
                "url": current_url,
                "hostname": validated[
                    "hostname"
                ],
                "resolved_addresses": validated[
                    "resolved_addresses"
                ],
                "status_code": status_code,
                "location": location,
            }
        )

        if (
            status_code
            not in {
                301,
                302,
                303,
                307,
                308,
            }
            or not location
        ):
            break

        if redirect_number >= MAX_REDIRECTS:
            raise DeepInspectionError(
                "The URL exceeded the redirect limit."
            )

        next_url = urljoin(
            current_url,
            location,
        )

        validate_url(
            next_url
        )

        response.close()
        current_url = next_url

    if response is None:
        raise DeepInspectionError(
            "No HTTP response was received."
        )

    final_url = current_url
    content_type = response.headers.get(
        "Content-Type",
        "",
    ).lower()

    body = b""
    truncated = False
    parser = PageMetadataParser()

    if (
        "text/html" in content_type
        or "application/xhtml+xml"
        in content_type
    ):
        body, truncated = read_limited_response(
            response
        )

        encoding = (
            response.encoding
            or "utf-8"
        )

        html_text = body.decode(
            encoding,
            errors="replace",
        )

        parser.feed(
            html_text
        )

    response.close()

    forms = external_form_findings(
        page_url=final_url,
        forms=parser.forms,
    )

    original_domain = (
        registered_domain_approximation(
            urlparse(
                url
            ).hostname or ""
        )
    )

    final_domain = (
        registered_domain_approximation(
            urlparse(
                final_url
            ).hostname or ""
        )
    )

    external_password_forms = [
        form
        for form in forms
        if form.get(
            "has_password"
        )
        and form.get(
            "external_destination"
        )
    ]

    findings = []

    if original_domain != final_domain:
        findings.append(
            "The final registered domain differs "
            "from the original URL domain."
        )

    if parser.password_input_count:
        findings.append(
            "The page contains at least one password field."
        )

    if external_password_forms:
        findings.append(
            "A password form submits to a different "
            "registered domain."
        )

    if final_url.lower().startswith(
        "http://"
    ):
        findings.append(
            "The final destination does not use HTTPS."
        )

    return {
        "submitted_url": url,
        "final_url": final_url,
        "original_domain": original_domain,
        "final_domain": final_domain,
        "domain_changed": (
            original_domain != final_domain
        ),
        "status_code": int(
            response.status_code
        ),
        "content_type": content_type,
        "page_title": parser.title,
        "html_bytes_read": len(
            body
        ),
        "html_truncated": truncated,
        "redirect_count": max(
            len(redirects) - 1,
            0,
        ),
        "redirect_chain": redirects,
        "form_count": len(
            forms
        ),
        "password_input_count": (
            parser.password_input_count
        ),
        "external_form_count": sum(
            1
            for form in forms
            if form.get(
                "external_destination"
            )
        ),
        "external_password_form_count": len(
            external_password_forms
        ),
        "forms": forms[:20],
        "findings": findings,
        "inspection_mode": (
            "manual-safe-static-inspection"
        ),
        "javascript_executed": False,
    }
