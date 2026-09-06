import pytest

from app.link_intelligence.deep_inspector import (
    DeepInspectionError,
    validate_url,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/",
        "ftp://example.com/file",
    ],
)
def test_internal_or_unsupported_urls_blocked(
    url,
):
    with pytest.raises(
        DeepInspectionError
    ):
        validate_url(
            url
        )


def test_public_https_url_allowed():
    result = validate_url(
        "https://example.com/"
    )

    assert (
        result["scheme"]
        == "https"
    )
