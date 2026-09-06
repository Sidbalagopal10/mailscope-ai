from __future__ import annotations

import json
import os
from typing import Any

import requests

from app.analyst.prompt_engine import (
    SYSTEM_INSTRUCTIONS,
)
from app.analyst.providers.base import (
    AIProvider,
    AIProviderError,
)


class OllamaAnalystProvider(
    AIProvider,
):
    provider_name = "ollama"

    def __init__(
        self,
    ) -> None:
        self.base_url = os.getenv(
            "OLLAMA_BASE_URL",
            "http://127.0.0.1:11434",
        )

        self.model_name = os.getenv(
            "OLLAMA_ANALYST_MODEL",
            "qwen3:8b",
        )

    def generate_json(
        self,
        prompt: str,
    ) -> dict[str, Any]:
        response = requests.post(
            (
                self.base_url.rstrip("/")
                + "/api/generate"
            ),

            json={
                "model": (
                    self.model_name
                ),

                "prompt": (
                    SYSTEM_INSTRUCTIONS
                    + "\n\n"
                    + prompt
                ),

                "stream": False,

                "format": "json",
            },

            timeout=180,
        )

        if (
            response.status_code
            >= 400
        ):
            raise AIProviderError(
                "Ollama request failed: "
                f"{response.status_code} "
                f"{response.text[:500]}"
            )

        payload = response.json()

        raw = payload.get(
            "response"
        )

        if not isinstance(
            raw,
            str,
        ):
            raise AIProviderError(
                "Ollama returned no response text."
            )

        try:
            parsed = json.loads(
                raw
            )

        except json.JSONDecodeError as error:
            raise AIProviderError(
                "Ollama did not return valid JSON."
            ) from error

        if not isinstance(
            parsed,
            dict,
        ):
            raise AIProviderError(
                "Ollama output must be "
                "a JSON object."
            )

        return parsed
