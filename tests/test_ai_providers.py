from __future__ import annotations

import os

from app.analyst.providers.factory import (
    get_ai_provider,
)
from app.analyst.providers.mock_provider import (
    MockAnalystProvider,
)


def test_mock_provider_selection(
    monkeypatch,
):
    monkeypatch.setenv(
        "AI_ANALYST_PROVIDER",
        "mock",
    )

    provider = (
        get_ai_provider()
    )

    assert isinstance(
        provider,
        MockAnalystProvider,
    )


def test_mock_provider_returns_json():
    provider = (
        MockAnalystProvider()
    )

    prompt = """
    {
      "investigation_id":
      "inv-test",

      "findings": [
        {
          "evidence_id": "E1",
          "title":
          "Possible brand impersonation"
        }
      ],

      "is_suspicious": true
    }
    """

    result = provider.generate_json(
        prompt
    )

    assert (
        result[
            "investigation_id"
        ]
        == "inv-test"
    )

    assert (
        result[
            "verdict"
        ]
        == "likely_phishing"
    )
