from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


TRACKING_PARAMETERS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "gclid",
    "fbclid",
    "mc_cid",
    "mc_eid",
}

IGNORED_PREFIXES = (
    "mailto:",
    "tel:",
    "javascript:",
)

IGNORED_DOMAINS = {
    "fonts.googleapis.com",
    "fonts.gstatic.com",
}


def normalize_url(url: str) -> str:
    url = url.strip()

    if not url:
        return ""

    if url.lower().startswith(IGNORED_PREFIXES):
        return ""

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        return ""

    domain = parsed.netloc.lower()

    if not domain:
        return ""

    if domain.startswith("www."):
        domain = domain[4:]

    if domain in IGNORED_DOMAINS:
        return ""

    cleaned_parameters = [
        (key, value)
        for key, value in parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )
        if key.lower() not in TRACKING_PARAMETERS
    ]

    cleaned_query = urlencode(
        cleaned_parameters,
        doseq=True,
    )

    cleaned_url = urlunparse(
        (
            parsed.scheme.lower(),
            domain,
            parsed.path or "/",
            parsed.params,
            cleaned_query,
            "",
        )
    )

    return cleaned_url


def clean_urls(urls: list[str]) -> list[str]:
    cleaned_urls = {
        normalized
        for url in urls
        if (normalized := normalize_url(url))
    }

    return sorted(cleaned_urls)
