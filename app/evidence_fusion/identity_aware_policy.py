from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit


SHARED_HOST_SUFFIXES = {
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "github.io",
    "blogspot.com",
    "weebly.com",
    "azurewebsites.net",
}

SENSITIVE_TERMS = {
    "login",
    "signin",
    "sign-in",
    "auth",
    "authenticate",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "password",
    "wallet",
    "billing",
}


@dataclass(frozen=True)
class IdentityAwareDecision:
    original_severity: float
    candidate_severity: float

    original_suspicious: bool
    candidate_suspicious: bool

    identity_state: str

    impersonation_detected: bool
    sensitive_behavior_detected: bool
    shared_host_detected: bool

    escalation_applied: bool

    reasons: tuple[str, ...]


def _hostname(
    url: str,
) -> str:
    value = str(url or "").strip()

    if "://" not in value:
        value = "https://" + value

    try:
        return (
            urlsplit(value).hostname
            or ""
        ).lower().rstrip(".")
    except ValueError:
        return ""


def _shared_host(
    hostname: str,
) -> bool:
    for suffix in SHARED_HOST_SUFFIXES:
        if (
            hostname == suffix
            or hostname.endswith(
                "." + suffix
            )
        ):
            return True

    return False


def _reason_text(
    reasons: Iterable[str],
) -> str:
    return " ".join(
        str(reason).lower()
        for reason in reasons
    )


def evaluate_identity_aware_candidate(
    *,
    url: str,
    severity: float,
    is_suspicious: bool,
    legacy_reasons: Iterable[str],
    identity_state: str,
) -> IdentityAwareDecision:
    """
    FINAL CORE POLICY CANDIDATE.

    Identity certainty and phishing risk remain separate.

    UNKNOWN alone:
        no risk.

    CONFLICTING alone:
        no risk.

    VERIFIED/SUPPORTED:
        never blanket-allow the URL.

    UNKNOWN + brand impersonation + corroborating behavior:
        escalate for investigation.

    This policy deliberately does NOT suppress threat-feed,
    malware, compromise, or other malicious evidence on
    verified domains.
    """

    severity = float(
        severity or 0.0
    )

    reasons = list(
        legacy_reasons or []
    )

    text = _reason_text(
        reasons
    )

    hostname = _hostname(
        url
    )

    impersonation = (
        "brand impersonation" in text
        or "impersonation" in text
    )

    sensitive = any(
        term in text
        for term in SENSITIVE_TERMS
    )

    shared_host = _shared_host(
        hostname
    )

    candidate_severity = severity
    candidate_suspicious = bool(
        is_suspicious
    )

    added_reasons = []

    escalation = False

    # Identity UNKNOWN is neutral.
    #
    # We escalate only when the OLD detector already
    # observed impersonation AND another independent
    # contextual signal exists.
    if (
        identity_state == "unknown"
        and impersonation
        and (
            sensitive
            or shared_host
        )
    ):
        escalation = True

        # Minimum investigation-level severity.
        #
        # This does not make identity itself malicious.
        candidate_severity = max(
            candidate_severity,
            6.0,
        )

        candidate_suspicious = True

        added_reasons.append(
            "Corroborated impersonation: claimed brand "
            "has no established organizational identity "
            "on this hostname."
        )

        if sensitive:
            added_reasons.append(
                "Impersonation is combined with "
                "credential/account-related language."
            )

        if shared_host:
            added_reasons.append(
                "Impersonation occurs on user-controlled "
                "shared hosting infrastructure."
            )

    # Explicitly do NOTHING for identity disagreement.
    if identity_state == "conflicting":
        added_reasons.append(
            "Identity sources disagree; this does not "
            "increase phishing risk by itself."
        )

    # Explicitly document that known identity is not
    # an allowlist.
    if identity_state in {
        "verified",
        "supported",
    }:
        added_reasons.append(
            "Established organizational identity does "
            "not override independent malicious evidence."
        )

    return IdentityAwareDecision(
        original_severity=severity,
        candidate_severity=round(
            candidate_severity,
            2,
        ),

        original_suspicious=bool(
            is_suspicious
        ),

        candidate_suspicious=(
            candidate_suspicious
        ),

        identity_state=identity_state,

        impersonation_detected=(
            impersonation
        ),

        sensitive_behavior_detected=(
            sensitive
        ),

        shared_host_detected=(
            shared_host
        ),

        escalation_applied=(
            escalation
        ),

        reasons=tuple(
            reasons
            + added_reasons
        ),
    )
