from __future__ import annotations

import os

from app.analyst.providers.base import (
    AIProvider,
    AIProviderError,
)
from app.analyst.providers.mock_provider import (
    MockAnalystProvider,
)
from app.analyst.providers.ollama_provider import (
    OllamaAnalystProvider,
)
from app.analyst.providers.openai_provider import (
    OpenAIAnalystProvider,
)


def get_ai_provider() -> AIProvider:
    name = os.getenv(
        "AI_ANALYST_PROVIDER",
        "mock",
    ).strip().lower()

    if name == "mock":
        return MockAnalystProvider()

    if name == "ollama":
        return OllamaAnalystProvider()

    if name == "openai":
        return OpenAIAnalystProvider()

    raise AIProviderError(
        f"Unknown AI_ANALYST_PROVIDER: {name}"
    )
