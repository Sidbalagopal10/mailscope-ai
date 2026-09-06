from __future__ import annotations

import base64

from app.gmail_observation.observer import (
    basic_link_risk,
    decode_base64url,
    extract_body_parts,
    extract_urls,
)


def encode(
    value: str,
) -> str:
    return base64.urlsafe_b64encode(
        value.encode(
            "utf-8"
        )
    ).decode(
        "ascii"
    ).rstrip("=")


def test_decode_base64url():
    assert decode_base64url(
        encode(
            "Hello professor"
        )
    ) == "Hello professor"


def test_extract_plain_body():
    payload = {
        "mimeType": "multipart/alternative",
        "parts": [
            {
                "mimeType": "text/plain",
                "body": {
                    "data": encode(
                        "Assignment due tonight."
                    )
                },
            },
            {
                "mimeType": "text/html",
                "body": {
                    "data": encode(
                        "<p>Assignment due tonight.</p>"
                    )
                },
            },
        ],
    }

    result = extract_body_parts(
        payload
    )

    assert (
        result[
            "selected_text"
        ]
        == "Assignment due tonight."
    )


def test_extract_urls():
    urls = extract_urls(
        (
            "Submit at https://blackboard.example.edu/course "
            "and visit https://example.edu."
        )
    )

    assert urls == [
        "https://blackboard.example.edu/course",
        "https://example.edu",
    ]


def test_normal_https_link_is_low():
    result = basic_link_risk(
        [
            "https://blackboard.example.edu/course"
        ]
    )

    assert result[
        "risk_score"
    ] < 35


def test_raw_ip_login_link_is_high():
    result = basic_link_risk(
        [
            "http://192.0.2.5/verify-password"
        ]
    )

    assert result[
        "risk_score"
    ] >= 70
