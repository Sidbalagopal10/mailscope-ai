from __future__ import annotations

from typing import Any

from app.analyst.openai_provider import (
    generate_report_json,
)
from app.analyst.providers.base import (
    AIProvider,
)


class OpenAIAnalystProvider(
    AIProvider,
):
    provider_name = "openai"

    def __init__(
        self,
    ) -> None:
        self.model_name = (
            "environment-configured"
        )

    def generate_json(
        self,
        prompt: str,
    ) -> dict[str, Any]:
        payload, model = (
            generate_report_json(
                prompt
            )
        )

        self.model_name = (
            model
        )

        return payload
