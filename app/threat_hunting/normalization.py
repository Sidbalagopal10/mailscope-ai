import ipaddress
from urllib.parse import urlsplit, urlunsplit


HASH_TYPES = {
    "md5",
    "sha1",
    "sha256",
}


def normalize_type(
    value: str | None,
) -> str | None:
    if value is None:
        return None

    normalized = (
        str(value)
        .strip()
        .lower()
    )

    aliases = {
        "hostname": "domain",
        "host": "domain",
        "sender": "email",
    }

    return aliases.get(
        normalized,
        normalized,
    )


def normalize_value(
    observable_type: str,
    value: str,
) -> str:
    value = str(
        value
    ).strip()

    if observable_type == "url":
        candidate = value

        if "://" not in candidate:
            candidate = (
                "https://"
                + candidate
            )

        try:
            parsed = urlsplit(
                candidate
            )

            hostname = (
                parsed.hostname
                or ""
            ).lower()

            if not hostname:
                return value

            scheme = (
                parsed.scheme
                or "https"
            ).lower()

            port = parsed.port

            netloc = hostname

            if (
                port is not None
                and not (
                    scheme == "https"
                    and port == 443
                )
                and not (
                    scheme == "http"
                    and port == 80
                )
            ):
                netloc = (
                    f"{hostname}:{port}"
                )

            return urlunsplit(
                (
                    scheme,
                    netloc,
                    parsed.path or "/",
                    parsed.query,
                    "",
                )
            )

        except (
            ValueError,
            TypeError,
        ):
            return value

    if observable_type == "domain":
        return (
            value.lower()
            .rstrip(".")
        )

    if observable_type == "ip":
        try:
            return str(
                ipaddress.ip_address(
                    value
                )
            )
        except ValueError:
            return value

    if (
        observable_type == "email"
        or observable_type
        in HASH_TYPES
    ):
        return value.lower()

    return value
