from __future__ import annotations

from abc import (
    ABC,
    abstractmethod,
)
from typing import Any


class AIProviderError(
    RuntimeError
):
    pass


class AIProvider(
    ABC,
):
    """
    Common interface for all AI analyst backends.
    """

    provider_name: str
    model_name: str

    @abstractmethod
    def generate_json(
        self,
        prompt: str,
    ) -> dict[str, Any]:
        raise NotImplementedError
