from __future__ import annotations

from dotenv import load_dotenv

import json
import os
from pathlib import Path
from typing import Any

import requests

from app.analyst.prompt_engine import (
    SYSTEM_INSTRUCTIONS,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(
    dotenv_path=PROJECT_ROOT / ".env"
)

OPENAI_RESPONSES_URL = (
    "https://api.openai.com/v1/responses"
)


class AnalystProviderError(
    RuntimeError
):
    pass


def _extract_text(
    payload: dict[str, Any],
) -> str:
    """
    Extract textual output from a Responses API result
    without depending on the OpenAI Python SDK.
    """

    if isinstance(
        payload.get(
            "output_text"
        ),
        str,
    ):
        return payload[
            "output_text"
        ]

    pieces = []

    for output_item in payload.get(
        "output",
        [],
    ):
        for content in output_item.get(
            "content",
            [],
        ):
            text = content.get(
                "text"
            )

            if isinstance(
                text,
                str,
            ):
                pieces.append(
                    text
                )

    return "\n".join(
        pieces
    ).strip()


def generate_report_json(
    prompt: str,
) -> tuple[
    dict[str, Any],
    str,
]:
    api_key = os.getenv(
        "OPENAI_API_KEY"
    )

    if not api_key:
        raise AnalystProviderError(
            "OPENAI_API_KEY is not configured."
        )

    model = os.getenv(
        "OPENAI_ANALYST_MODEL",
        "gpt-5.6-luna",
    )

    response = requests.post(
        OPENAI_RESPONSES_URL,

        headers={
            "Authorization": (
                f"Bearer {api_key}"
            ),

            "Content-Type": (
                "application/json"
            ),
        },

        json={
            "model": model,

            "instructions": (
                SYSTEM_INSTRUCTIONS
            ),

            "input": prompt,
        },

        timeout=120,
    )

    if response.status_code >= 400:
        raise AnalystProviderError(
            "OpenAI request failed: "
            f"{response.status_code} "
            f"{response.text[:500]}"
        )

    payload = response.json()

    text = _extract_text(
        payload
    )

    if not text:
        raise AnalystProviderError(
            "Model returned no textual output."
        )

    # Tolerate markdown JSON fences if the model
    # ignores the JSON-only instruction.
    cleaned = text.strip()

    if cleaned.startswith(
        "```"
    ):
        lines = cleaned.splitlines()

        if lines:
            lines = lines[
                1:
            ]

        if (
            lines
            and lines[-1].strip()
            == "```"
        ):
            lines = lines[
                :-1
            ]

        cleaned = "\n".join(
            lines
        ).strip()

        if cleaned.lower().startswith(
            "json\n"
        ):
            cleaned = cleaned[
                5:
            ]

    try:
        parsed = json.loads(
            cleaned
        )

    except json.JSONDecodeError as error:
        raise AnalystProviderError(
            "Model did not return valid JSON: "
            f"{error}"
        ) from error

    if not isinstance(
        parsed,
        dict,
    ):
        raise AnalystProviderError(
            "Analyst output must be a JSON object."
        )

    return (
        parsed,
        model,
    )
