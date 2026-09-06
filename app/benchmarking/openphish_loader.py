from __future__ import annotations

from pathlib import Path

import requests

from app.benchmarking.models import (
    BenchmarkCase,
)


# Official OpenPhish Community Feed target linked from
# OpenPhish's Phishing Feeds page.
OPENPHISH_COMMUNITY_URL = (
    "https://raw.githubusercontent.com/"
    "openphish/public_feed/"
    "refs/heads/main/feed.txt"
)

OUTPUT = Path(
    "data/benchmarking/phishing/"
    "openphish_community_feed.txt"
)

USER_AGENT = (
    "AI-Mail-Phishing-Detector/"
    "IndependentBenchmark/1.0"
)


def download_openphish(
    *,
    force: bool = False,
) -> Path:
    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if (
        OUTPUT.exists()
        and OUTPUT.stat().st_size > 0
        and not force
    ):
        return OUTPUT

    response = requests.get(
        OPENPHISH_COMMUNITY_URL,
        timeout=120,
        headers={
            "User-Agent": USER_AGENT,
        },
    )

    response.raise_for_status()

    text = response.text

    urls = [
        line.strip()
        for line in text.splitlines()
        if line.strip().lower().startswith(
            (
                "http://",
                "https://",
            )
        )
    ]

    if not urls:
        raise RuntimeError(
            "OpenPhish Community Feed contained no URLs."
        )

    OUTPUT.write_text(
        "\n".join(urls) + "\n",
        encoding="utf-8",
    )

    return OUTPUT


def load_openphish_cases(
    *,
    limit: int = 1000,
    force_refresh: bool = False,
) -> list[BenchmarkCase]:
    path = download_openphish(
        force=force_refresh
    )

    urls = [
        line.strip()
        for line in path.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
        if line.strip().lower().startswith(
            (
                "http://",
                "https://",
            )
        )
    ]

    seen = set()
    cases = []

    for url in urls:
        if url in seen:
            continue

        seen.add(
            url
        )

        cases.append(
            BenchmarkCase(
                value=url,
                expected_label="malicious",
                source="openphish_holdout",
                metadata={
                    "ground_truth_type": (
                        "phishing"
                    ),
                    "detector_may_use_source": False,
                },
            )
        )

        if len(
            cases
        ) >= limit:
            break

    return cases


if __name__ == "__main__":
    cases = load_openphish_cases(
        limit=20,
        force_refresh=True,
    )

    print(
        "OpenPhish cases:",
        len(cases),
    )

    for case in cases[:5]:
        print(
            case.value
        )
