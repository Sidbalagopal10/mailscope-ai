from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urljoin

import requests


DOWNLOAD_PAGE = (
    "https://www.gleif.org/en/lei-data/"
    "gleif-concatenated-file/"
    "download-the-concatenated-file"
)

DOWNLOAD_DIR = Path(
    "data/global_entity_registry/gleif"
)

USER_AGENT = (
    "AI-Mail-Phishing-Detector/"
    "GlobalEntityRegistry/1.0"
)


class GLEIFBulkDownloadError(Exception):
    pass


def session() -> requests.Session:
    value = requests.Session()

    value.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
            ),
        }
    )

    return value


def fetch_download_page() -> str:
    with session() as client:
        response = client.get(
            DOWNLOAD_PAGE,
            timeout=60,
        )

        response.raise_for_status()

        return response.text


def discover_level1_zip_url() -> str:
    """
    Discover GLEIF's current Level 1 LEI-CDF ZIP endpoint.

    GLEIF does not expose a conventional *.zip href. The website
    currently points to a leidata.gleif.org API endpoint ending
    with /zip.
    """
    html = fetch_download_page()

    # Absolute links.
    absolute_candidates = re.findall(
        r'''https://leidata\.gleif\.org/
            api/v1/concatenated-files/
            [^"'<> \t\r\n]+?/zip
        ''',
        html,
        flags=(
            re.IGNORECASE
            | re.VERBOSE
        ),
    )

    # Escaped or relative hrefs if page rendering changes.
    relative_candidates = re.findall(
        r'''(?:href=["'])
            (?P<url>
                /?api/v1/concatenated-files/
                [^"'<> \t\r\n]+?/zip
            )
        ''',
        html,
        flags=(
            re.IGNORECASE
            | re.VERBOSE
        ),
    )

    candidates = list(
        dict.fromkeys(
            [
                candidate.replace(
                    "&amp;",
                    "&",
                )
                for candidate
                in absolute_candidates
            ]
            + [
                urljoin(
                    "https://leidata.gleif.org/",
                    candidate,
                )
                for candidate
                in relative_candidates
            ]
        )
    )

    if not candidates:
        # Broader fallback: extract any leidata API download link.
        fallback = re.findall(
            r'''https://leidata\.gleif\.org/
                api/v1/concatenated-files/
                [^"'<> \t\r\n]+
            ''',
            html,
            flags=(
                re.IGNORECASE
                | re.VERBOSE
            ),
        )

        candidates = [
            candidate.replace(
                "&amp;",
                "&",
            )
            for candidate in fallback
            if candidate.rstrip(
                "/"
            ).endswith(
                "/zip"
            )
        ]

    if not candidates:
        raise GLEIFBulkDownloadError(
            "Could not discover a GLEIF concatenated-file "
            "download endpoint from the current page."
        )

    # Level 1 currently uses the LEI concatenated-file family,
    # whereas Level 2 uses RR and reporting-exception families.
    level1_candidates = []

    for url in candidates:
        lowered = url.lower()

        if any(
            token in lowered
            for token in (
                "/lei2/",
                "/lei/",
            )
        ):
            level1_candidates.append(
                url
            )

    if not level1_candidates:
        raise GLEIFBulkDownloadError(
            "GLEIF download endpoints were found, but none "
            "could be identified confidently as Level 1."
        )

    return level1_candidates[0]


def inspect_download(
    url: str,
) -> dict:
    """
    Validate the remote ZIP endpoint without downloading the file.
    """
    with session() as client:
        response = client.get(
            url,
            headers={
                "Range": "bytes=0-0",
                "Accept": (
                    "application/zip,"
                    "application/octet-stream,*/*"
                ),
            },
            stream=True,
            allow_redirects=True,
            timeout=60,
        )

        if response.status_code not in {
            200,
            206,
        }:
            response.raise_for_status()

        content_range = response.headers.get(
            "Content-Range"
        )

        total_size = None

        if (
            content_range
            and "/"
            in content_range
        ):
            raw_total = content_range.rsplit(
                "/",
                1,
            )[-1]

            if raw_total.isdigit():
                total_size = int(
                    raw_total
                )

        if total_size is None:
            raw_length = response.headers.get(
                "Content-Length"
            )

            if (
                raw_length
                and raw_length.isdigit()
                and response.status_code == 200
            ):
                total_size = int(
                    raw_length
                )

        result = {
            "status_code": (
                response.status_code
            ),
            "final_url": (
                response.url
            ),
            "content_type": (
                response.headers.get(
                    "Content-Type"
                )
            ),
            "content_length": (
                response.headers.get(
                    "Content-Length"
                )
            ),
            "content_range": (
                content_range
            ),
            "total_size_bytes": (
                total_size
            ),
        }

        response.close()

        return result


def download_level1_zip(
    *,
    force: bool = False,
) -> Path:
    DOWNLOAD_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    url = discover_level1_zip_url()

    metadata = inspect_download(
        url
    )

    filename = (
        "gleif_level1_latest.zip"
    )

    destination = (
        DOWNLOAD_DIR
        / filename
    )

    if (
        destination.exists()
        and destination.stat().st_size > 0
        and not force
    ):
        expected = metadata.get(
            "total_size_bytes"
        )

        if (
            expected is None
            or destination.stat().st_size
            == expected
        ):
            return destination

    temporary = destination.with_suffix(
        ".zip.part"
    )

    existing_size = (
        temporary.stat().st_size
        if temporary.exists()
        else 0
    )

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": (
            "application/zip,"
            "application/octet-stream,*/*"
        ),
    }

    if existing_size:
        headers[
            "Range"
        ] = (
            f"bytes={existing_size}-"
        )

    with requests.get(
        url,
        headers=headers,
        stream=True,
        allow_redirects=True,
        timeout=180,
    ) as response:
        if (
            existing_size
            and response.status_code == 206
        ):
            mode = "ab"

        else:
            mode = "wb"
            existing_size = 0

        response.raise_for_status()

        with temporary.open(
            mode
        ) as handle:
            downloaded = (
                existing_size
            )

            for chunk in response.iter_content(
                chunk_size=1024 * 1024
            ):
                if not chunk:
                    continue

                handle.write(
                    chunk
                )

                downloaded += len(
                    chunk
                )

                if (
                    downloaded
                    % (
                        50
                        * 1024
                        * 1024
                    )
                    < len(
                        chunk
                    )
                ):
                    print(
                        "Downloaded:",
                        f"{downloaded / (1024 ** 2):.1f} MB",
                    )

    expected = metadata.get(
        "total_size_bytes"
    )

    actual = temporary.stat().st_size

    if (
        expected is not None
        and actual != expected
    ):
        raise GLEIFBulkDownloadError(
            "Download size mismatch: "
            f"expected {expected} bytes, "
            f"received {actual} bytes."
        )

    temporary.replace(
        destination
    )

    return destination


if __name__ == "__main__":
    url = discover_level1_zip_url()

    print(
        "Level 1 URL:"
    )
    print(
        url
    )

    print()

    metadata = inspect_download(
        url
    )

    print(
        "Remote metadata:"
    )

    for key, value in metadata.items():
        print(
            f"{key}: {value}"
        )

    print()

    path = download_level1_zip()

    print(
        "Downloaded:"
    )

    print(
        path
    )
