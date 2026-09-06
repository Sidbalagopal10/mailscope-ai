import ipaddress
from dataclasses import dataclass
from typing import List
from urllib.parse import urlparse

from app.services.identity_risk_bridge import (
    apply_identity_risk_policy,
)


SUSPICIOUS_WORDS = {
    "login",
    "verify",
    "verification",
    "update",
    "secure",
    "security",
    "account",
    "password",
    "confirm",
    "payment",
    "billing",
    "wallet",
    "urgent",
    "suspended",
    "unlock",
    "signin",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "cutt.ly",
    "is.gd",
}

TRUSTED_BRAND_DOMAINS = {
    "google": {"google.com"},
    "gmail": {"gmail.com", "google.com"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazonaws.com"},
    "microsoft": {"microsoft.com", "office.com", "live.com"},
    "apple": {"apple.com", "icloud.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "facebookmail.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
}


@dataclass
class RiskResult:
    url: str
    severity: float
    risk_level: str
    is_suspicious: bool
    reasons: List[str]


def normalize_domain(domain: str) -> str:
    domain = domain.lower().strip()

    if ":" in domain:
        domain = domain.split(":", 1)[0]

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def is_ip_address(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def is_trusted_brand_domain(domain: str, brand: str) -> bool:
    trusted_domains = TRUSTED_BRAND_DOMAINS.get(brand, set())

    return any(
        domain == trusted
        or domain.endswith("." + trusted)
        for trusted in trusted_domains
    )


def get_risk_level(severity: float) -> str:
    if severity <= 2:
        return "LOW"
    if severity <= 4:
        return "GUARDED"
    if severity <= 6:
        return "MODERATE"
    if severity <= 8:
        return "HIGH"

    return "CRITICAL"


def analyze_url(url: str) -> RiskResult:
    reasons = []
    score = 0

    parsed = urlparse(url)
    domain = normalize_domain(parsed.netloc)
    url_lower = url.lower()

    if not domain:
        return RiskResult(
            url=url,
            severity=0.0,
            risk_level="LOW",
            is_suspicious=False,
            reasons=["URL could not be parsed"],
        )

    if parsed.scheme != "https":
        reasons.append("URL does not use HTTPS")
        score += 15

    if is_ip_address(domain):
        reasons.append("URL uses an IP address")
        score += 35

    if len(url) > 150:
        reasons.append("URL is extremely long")
        score += 15
    elif len(url) > 100:
        reasons.append("URL is unusually long")
        score += 8

    matched_words = sorted({
        word
        for word in SUSPICIOUS_WORDS
        if word in url_lower
    })

    if matched_words:
        reasons.append(
            "Suspicious terms detected: "
            + ", ".join(matched_words)
        )
        score += min(20, len(matched_words) * 4)

    if "@" in url:
        reasons.append("URL contains an @ symbol")
        score += 25

    if domain.count("-") >= 2:
        reasons.append("Domain contains multiple hyphens")
        score += 10

    if domain.startswith("xn--") or ".xn--" in domain:
        reasons.append("Domain uses punycode")
        score += 25

    if domain in URL_SHORTENERS:
        reasons.append("URL uses a shortening service")
        score += 20

    if domain.count(".") >= 4:
        reasons.append("Domain contains many subdomains")
        score += 10

    for brand in TRUSTED_BRAND_DOMAINS:
        if brand in domain and not is_trusted_brand_domain(domain, brand):
            reasons.append(
                f"Possible brand impersonation: {brand}"
            )
            score += 30
            break

    severity = round(min(score, 100) / 10, 1)

    identity_adjustment = apply_identity_risk_policy(
        url=url,
        severity=severity,
        is_suspicious=(
            severity >= 5
        ),
        reasons=reasons,
    )

    severity = float(
        identity_adjustment[
            "severity"
        ]
    )

    is_suspicious = bool(
        identity_adjustment[
            "is_suspicious"
        ]
    )

    reasons = list(
        identity_adjustment[
            "reasons"
        ]
    )

    risk_level = get_risk_level(
        severity
    )

    return RiskResult(
        url=url,
        severity=severity,
        risk_level=risk_level,
        is_suspicious=is_suspicious,
        reasons=reasons,
    )
