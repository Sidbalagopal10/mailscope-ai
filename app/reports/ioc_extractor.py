from __future__ import annotations

import ipaddress
import re
from urllib.parse import (
    urlsplit,
)

from app.analyst.evidence import (
    InvestigationEvidence,
)
from app.reports.models import (
    IOC,
)


EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+"
    r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

HASH_PATTERNS = {
    "md5": re.compile(
        r"\b[a-fA-F0-9]{32}\b"
    ),

    "sha1": re.compile(
        r"\b[a-fA-F0-9]{40}\b"
    ),

    "sha256": re.compile(
        r"\b[a-fA-F0-9]{64}\b"
    ),
}


def _add_unique(
    output: list[IOC],
    seen: set[tuple[str, str]],
    *,
    ioc_type: str,
    value: str,
    source: str,
    confidence: float | None = None,
) -> None:
    cleaned = str(
        value or ""
    ).strip()

    if not cleaned:
        return

    key = (
        ioc_type,
        cleaned.lower(),
    )

    if key in seen:
        return

    seen.add(
        key
    )

    output.append(
        IOC(
            type=ioc_type,
            value=cleaned,
            source=source,
            confidence=confidence,
        )
    )


def extract_iocs(
    evidence: InvestigationEvidence,
) -> list[IOC]:
    """
    Extract only observables that already exist
    inside the investigation evidence.

    No external lookup occurs here.
    """

    output: list[IOC] = []

    seen: set[
        tuple[str, str]
    ] = set()

    target = evidence.target

    # ---------------------------------------
    # Primary URL
    # ---------------------------------------

    if evidence.target_type == "url":
        _add_unique(
            output,
            seen,
            ioc_type="url",
            value=target,
            source="investigation_target",
            confidence=1.0,
        )

        try:
            parsed = urlsplit(
                target
            )

            hostname = (
                parsed.hostname
                or ""
            ).lower()

            if hostname:
                _add_unique(
                    output,
                    seen,
                    ioc_type="hostname",
                    value=hostname,
                    source="investigation_target",
                    confidence=1.0,
                )

                try:
                    ipaddress.ip_address(
                        hostname
                    )

                    _add_unique(
                        output,
                        seen,
                        ioc_type="ip",
                        value=hostname,
                        source="investigation_target",
                        confidence=1.0,
                    )

                except ValueError:
                    pass

        except ValueError:
            pass

    # ---------------------------------------
    # Identity domain
    # ---------------------------------------

    canonical = (
        evidence.identity.get(
            "canonical_domain"
        )
    )

    if canonical:
        _add_unique(
            output,
            seen,
            ioc_type="domain",
            value=str(
                canonical
            ),
            source="identity_engine",
        )

    # ---------------------------------------
    # Search deterministic finding text
    # ---------------------------------------

    all_text = "\n".join(
        [
            evidence.target,
            *[
                finding.title
                + " "
                + finding.description

                for finding
                in evidence.findings
            ],
        ]
    )

    for email in EMAIL_RE.findall(
        all_text
    ):
        _add_unique(
            output,
            seen,
            ioc_type="email",
            value=email,
            source="deterministic_evidence",
        )

    for hash_type, pattern in (
        HASH_PATTERNS.items()
    ):
        for value in pattern.findall(
            all_text
        ):
            _add_unique(
                output,
                seen,
                ioc_type=hash_type,
                value=value,
                source="deterministic_evidence",
            )

    return output
