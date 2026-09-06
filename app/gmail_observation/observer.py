from __future__ import annotations

import base64
import html
import json
import re
from email.utils import parseaddr
from pathlib import Path
from typing import Any

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from app.email_authentication.header_parser import (
    parse_email_authentication,
)
from app.email_security.contextual_decision import (
    contextual_email_decision,
)
from app.domain_intelligence.unified_profile import (
    analyze_unified_domain_profile,
)


DEFAULT_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
]

TOKEN_CANDIDATES = [
    Path("token.json"),
    Path("app/gmail/token.json"),
]

CREDENTIAL_CANDIDATES = [
    Path("credentials.json"),
    Path("app/gmail/credentials.json"),
]

URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"\]\)]+",
    re.IGNORECASE,
)


class GmailObservationError(Exception):
    pass


def find_existing_path(
    candidates: list[Path],
) -> Path:
    for candidate in candidates:
        if candidate.exists():
            return candidate

    raise GmailObservationError(
        "Required Gmail OAuth file was not found. "
        f"Checked: {[str(path) for path in candidates]}"
    )


def get_gmail_service():
    token_path = find_existing_path(
        TOKEN_CANDIDATES
    )

    credentials_path = find_existing_path(
        CREDENTIAL_CANDIDATES
    )

    credentials = Credentials.from_authorized_user_file(
        str(token_path)
    )

    if credentials.expired and credentials.refresh_token:
        credentials.refresh(
            Request()
        )

        token_path.write_text(
            credentials.to_json(),
            encoding="utf-8",
        )

    if not credentials.valid:
        raise GmailObservationError(
            "Gmail OAuth credentials are invalid. "
            "Run your existing Gmail connection flow again."
        )

    return build(
        "gmail",
        "v1",
        credentials=credentials,
        cache_discovery=False,
    )


def decode_base64url(
    value: str | None,
) -> str:
    if not value:
        return ""

    padding = "=" * (
        -len(value) % 4
    )

    try:
        decoded = base64.urlsafe_b64decode(
            value + padding
        )

        return decoded.decode(
            "utf-8",
            errors="replace",
        )

    except Exception:
        return ""


def strip_html(
    value: str,
) -> str:
    without_scripts = re.sub(
        r"(?is)<(script|style).*?>.*?</\1>",
        " ",
        value,
    )

    without_tags = re.sub(
        r"(?s)<[^>]+>",
        " ",
        without_scripts,
    )

    return re.sub(
        r"\s+",
        " ",
        html.unescape(
            without_tags
        ),
    ).strip()


def extract_body_parts(
    payload: dict[str, Any] | None,
) -> dict[str, str]:
    plain_parts: list[str] = []
    html_parts: list[str] = []

    def walk(
        part: dict[str, Any],
    ) -> None:
        mime_type = str(
            part.get(
                "mimeType",
                "",
            )
        ).lower()

        body = part.get(
            "body",
            {},
        )

        data = body.get(
            "data"
        )

        if data:
            decoded = decode_base64url(
                data
            )

            if mime_type == "text/plain":
                plain_parts.append(
                    decoded
                )

            elif mime_type == "text/html":
                html_parts.append(
                    decoded
                )

        for child in part.get(
            "parts",
            [],
        ):
            if isinstance(
                child,
                dict,
            ):
                walk(
                    child
                )

    if payload:
        walk(
            payload
        )

    plain_text = "\n".join(
        plain_parts
    ).strip()

    html_text = "\n".join(
        html_parts
    ).strip()

    selected_text = (
        plain_text
        if plain_text
        else strip_html(
            html_text
        )
    )

    return {
        "plain_text": plain_text,
        "html_text": html_text,
        "selected_text": selected_text,
    }


def header_value(
    headers: list[dict[str, str]],
    name: str,
) -> str:
    target = name.lower()

    for header in headers:
        if str(
            header.get(
                "name",
                "",
            )
        ).lower() == target:
            return str(
                header.get(
                    "value",
                    "",
                )
            )

    return ""


def sender_address(
    from_header: str,
) -> str:
    _, address = parseaddr(
        from_header
    )

    return address.lower().strip()


def sender_domain(
    address: str,
) -> str:
    if "@" not in address:
        return ""

    return address.rsplit(
        "@",
        1,
    )[1].lower().rstrip(".")


def extract_urls(
    *values: str,
) -> list[str]:
    urls: list[str] = []

    for value in values:
        for match in URL_PATTERN.findall(
            value or ""
        ):
            cleaned = match.rstrip(
                ".,;:!?]})>'\""
            )

            if cleaned not in urls:
                urls.append(
                    cleaned
                )

    return urls


def count_sender_messages(
    service,
    address: str,
    *,
    exclude_message_id: str | None = None,
) -> int:
    if not address:
        return 0

    response = (
        service.users()
        .messages()
        .list(
            userId="me",
            q=f"from:({address})",
            maxResults=5,
        )
        .execute()
    )

    message_ids = [
        item.get(
            "id"
        )
        for item in response.get(
            "messages",
            [],
        )
    ]

    return len(
        [
            message_id
            for message_id in message_ids
            if (
                message_id
                and message_id
                != exclude_message_id
            )
        ]
    )


def thread_message_count(
    service,
    thread_id: str | None,
) -> int:
    if not thread_id:
        return 1

    thread = (
        service.users()
        .threads()
        .get(
            userId="me",
            id=thread_id,
            format="minimal",
        )
        .execute()
    )

    return len(
        thread.get(
            "messages",
            [],
        )
    )


def basic_link_risk(
    urls: list[str],
) -> dict[str, Any]:
    """
    Observation-only URL triage.

    This intentionally avoids calling every external intelligence
    source for every mailbox message. Deep URL analysis can be
    triggered manually later.
    """
    score = 0.0
    reasons: list[str] = []

    suspicious_terms = {
        "verify",
        "password",
        "credential",
        "secure-login",
        "account-update",
        "gift-card",
        "wallet",
        "payment",
    }

    for url in urls:
        lowered = url.lower()

        if lowered.startswith(
            "http://"
        ):
            score = max(
                score,
                15.0,
            )

            reasons.append(
                f"Unencrypted HTTP link: {url}"
            )

        if any(
            term in lowered
            for term in suspicious_terms
        ):
            score = max(
                score,
                35.0,
            )

            reasons.append(
                f"Sensitive-action wording in URL: {url}"
            )

        if re.search(
            r"https?://(?:\d{1,3}\.){3}\d{1,3}",
            lowered,
        ):
            score = max(
                score,
                70.0,
            )

            reasons.append(
                f"URL uses a raw IP address: {url}"
            )

        if "@" in lowered.split(
            "://",
            1,
        )[-1].split(
            "/",
            1,
        )[0]:
            score = max(
                score,
                65.0,
            )

            reasons.append(
                f"URL authority contains @: {url}"
            )

    return {
        "risk_score": score,
        "reasons": reasons,
    }


def should_deep_analyze_links(
    *,
    preliminary_risk_level: str,
    basic_link_score: float,
    urls: list[str],
) -> bool:
    """
    Run expensive URL intelligence only when preliminary evidence
    justifies it.
    """
    if not urls:
        return False

    return bool(
        preliminary_risk_level
        in {
            "moderate",
            "high",
            "critical",
        }
        or float(
            basic_link_score
            or 0
        )
        >= 35.0
    )


def safe_deep_url_analysis(
    url: str,
) -> dict[str, Any]:
    """
    Analyze one URL without allowing a failed external source to
    crash Gmail observation mode.
    """
    try:
        profile = analyze_unified_domain_profile(
            url,
            force_refresh=False,
            include_ct_subdomains=False,
        )

        return {
            "url": url,
            "available": True,
            "error": None,
            "final_score": profile.get(
                "final_score",
                0,
            ),
            "risk_level": profile.get(
                "risk_level",
                "unknown",
            ),
            "classification": profile.get(
                "classification",
                "unknown",
            ),
            "recommendation": profile.get(
                "recommendation",
                "",
            ),
            "reasons": profile.get(
                "reasons",
                [],
            ),
            "evidence_summary": profile.get(
                "evidence_summary",
                {},
            ),
            "global_brand_intelligence": profile.get(
                "global_brand_intelligence",
                {},
            ),
            "threatfox_intelligence": profile.get(
                "threatfox_intelligence",
                {},
            ),
            "unavailable_sources": profile.get(
                "unavailable_sources",
                [],
            ),
        }

    except Exception as error:
        return {
            "url": url,
            "available": False,
            "error": str(
                error
            ),
            "final_score": 0.0,
            "risk_level": "unknown",
            "classification": "unavailable",
            "recommendation": (
                "Deep URL analysis was unavailable. "
                "Review the link manually."
            ),
            "reasons": [],
            "evidence_summary": {},
            "global_brand_intelligence": {},
            "threatfox_intelligence": {},
            "unavailable_sources": [],
        }


def deep_analyze_urls(
    urls: list[str],
    *,
    maximum_urls: int = 5,
) -> dict[str, Any]:
    """
    Analyze a bounded number of links to avoid excessive API calls.
    """
    safe_limit = max(
        1,
        min(
            int(
                maximum_urls
            ),
            10,
        ),
    )

    selected_urls = urls[
        :safe_limit
    ]

    results = [
        safe_deep_url_analysis(
            url
        )
        for url in selected_urls
    ]

    available_results = [
        result
        for result in results
        if result.get(
            "available"
        )
    ]

    highest_score = max(
        (
            float(
                result.get(
                    "final_score",
                    0,
                )
                or 0
            )
            for result in available_results
        ),
        default=0.0,
    )

    highest_risk_result = max(
        available_results,
        key=lambda result: float(
            result.get(
                "final_score",
                0,
            )
            or 0
        ),
        default=None,
    )

    return {
        "performed": True,
        "requested_url_count": len(
            urls
        ),
        "analyzed_url_count": len(
            results
        ),
        "skipped_url_count": max(
            0,
            len(
                urls
            )
            - len(
                results
            ),
        ),
        "highest_score": round(
            highest_score,
            2,
        ),
        "highest_risk_url": (
            highest_risk_result.get(
                "url"
            )
            if highest_risk_result
            else None
        ),
        "results": results,
    }


def analyze_message(
    service,
    message_stub: dict[str, Any],
) -> dict[str, Any]:
    message_id = str(
        message_stub.get(
            "id",
            "",
        )
    )

    message = (
        service.users()
        .messages()
        .get(
            userId="me",
            id=message_id,
            format="full",
        )
        .execute()
    )

    payload = message.get(
        "payload",
        {},
    )

    headers = payload.get(
        "headers",
        [],
    )

    bodies = extract_body_parts(
        payload
    )

    subject = header_value(
        headers,
        "Subject",
    )

    from_header = header_value(
        headers,
        "From",
    )

    address = sender_address(
        from_header
    )

    domain = sender_domain(
        address
    )

    urls = extract_urls(
        bodies["plain_text"],
        bodies["html_text"],
    )

    link_analysis = basic_link_risk(
        urls
    )

    authentication = parse_email_authentication(
        headers
    )

    previous_sender_count = count_sender_messages(
        service,
        address,
        exclude_message_id=message_id,
    )

    thread_count = thread_message_count(
        service,
        message.get(
            "threadId"
        ),
    )

    known_sender = (
        previous_sender_count >= 1
    )

    existing_thread = (
        thread_count >= 2
    )

    # Domain verification is intentionally conservative here.
    # Authentication and prior sender history are considered,
    # but this observation mode does not silently whitelist domains.
    sender_domain_verified = bool(
        domain
        and authentication.get(
            "dmarc",
            {},
        ).get(
            "result"
        )
        == "pass"
    )

    preliminary_decision = contextual_email_decision(
        subject=subject,
        body=bodies[
            "selected_text"
        ][
            :20000
        ],
        authentication=authentication,
        link_risk_score=link_analysis[
            "risk_score"
        ],
        attachment_risk_score=0.0,
        known_sender=known_sender,
        existing_thread=existing_thread,
        sender_domain_verified=(
            sender_domain_verified
        ),
    )

    deep_analysis_required = should_deep_analyze_links(
        preliminary_risk_level=(
            preliminary_decision.get(
                "risk_level",
                "low",
            )
        ),
        basic_link_score=link_analysis.get(
            "risk_score",
            0,
        ),
        urls=urls,
    )

    if deep_analysis_required:
        deep_link_analysis = deep_analyze_urls(
            urls,
            maximum_urls=5,
        )

    else:
        deep_link_analysis = {
            "performed": False,
            "reason": (
                "Preliminary message and URL evidence did "
                "not justify external deep analysis."
            ),
            "requested_url_count": len(
                urls
            ),
            "analyzed_url_count": 0,
            "skipped_url_count": len(
                urls
            ),
            "highest_score": 0.0,
            "highest_risk_url": None,
            "results": [],
        }

    combined_link_score = max(
        float(
            link_analysis.get(
                "risk_score",
                0,
            )
            or 0
        ),
        float(
            deep_link_analysis.get(
                "highest_score",
                0,
            )
            or 0
        ),
    )

    decision = contextual_email_decision(
        subject=subject,
        body=bodies[
            "selected_text"
        ][
            :20000
        ],
        authentication=authentication,
        link_risk_score=(
            combined_link_score
        ),
        attachment_risk_score=0.0,
        known_sender=known_sender,
        existing_thread=existing_thread,
        sender_domain_verified=(
            sender_domain_verified
        ),
    )

    return {
        "message_id": message_id,
        "thread_id": message.get(
            "threadId"
        ),
        "internal_date": message.get(
            "internalDate"
        ),
        "label_ids": message.get(
            "labelIds",
            [],
        ),
        "subject": subject,
        "from_header": from_header,
        "sender_address": address,
        "sender_domain": domain,
        "snippet": message.get(
            "snippet",
            "",
        ),
        "body_preview": bodies[
            "selected_text"
        ][
            :1000
        ],
        "urls": urls,
        "url_count": len(
            urls
        ),
        "link_observation": link_analysis,
        "preliminary_contextual_decision": (
            preliminary_decision
        ),
        "deep_link_analysis_required": (
            deep_analysis_required
        ),
        "deep_link_analysis": (
            deep_link_analysis
        ),
        "combined_link_risk_score": (
            combined_link_score
        ),
        "authentication": authentication,
        "previous_sender_count": (
            previous_sender_count
        ),
        "known_sender": known_sender,
        "thread_message_count": (
            thread_count
        ),
        "existing_thread": (
            existing_thread
        ),
        "sender_domain_verified": (
            sender_domain_verified
        ),
        "contextual_decision": (
            decision
        ),
        "observation_only": True,
        "gmail_modified": False,
    }


def observe_recent_messages(
    *,
    max_results: int = 10,
    query: str = "in:inbox newer_than:14d",
) -> dict[str, Any]:
    service = get_gmail_service()

    safe_max = max(
        1,
        min(
            int(
                max_results
            ),
            25,
        ),
    )

    response = (
        service.users()
        .messages()
        .list(
            userId="me",
            q=query,
            maxResults=safe_max,
        )
        .execute()
    )

    results: list[
        dict[str, Any]
    ] = []

    errors: list[
        dict[str, str]
    ] = []

    for message_stub in response.get(
        "messages",
        [],
    ):
        try:
            results.append(
                analyze_message(
                    service,
                    message_stub,
                )
            )

        except Exception as error:
            errors.append(
                {
                    "message_id": str(
                        message_stub.get(
                            "id",
                            "",
                        )
                    ),
                    "error": str(
                        error
                    ),
                }
            )

    summary = {
        "messages_analyzed": len(
            results
        ),
        "low": sum(
            1
            for result in results
            if result[
                "contextual_decision"
            ][
                "risk_level"
            ]
            == "low"
        ),
        "moderate": sum(
            1
            for result in results
            if result[
                "contextual_decision"
            ][
                "risk_level"
            ]
            == "moderate"
        ),
        "high": sum(
            1
            for result in results
            if result[
                "contextual_decision"
            ][
                "risk_level"
            ]
            == "high"
        ),
        "critical": sum(
            1
            for result in results
            if result[
                "contextual_decision"
            ][
                "risk_level"
            ]
            == "critical"
        ),
        "errors": len(
            errors
        ),
    }

    return {
        "query": query,
        "observation_only": True,
        "gmail_modified": False,
        "summary": summary,
        "messages": results,
        "errors": errors,
    }


def save_observation_report(
    report: dict[str, Any],
) -> Path:
    output_directory = Path(
        "data/gmail_observation"
    )

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path = (
        output_directory
        / "latest_observation.json"
    )

    output_path.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    return output_path
