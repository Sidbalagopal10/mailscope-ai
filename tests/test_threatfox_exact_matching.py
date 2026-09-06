from __future__ import annotations

from app.threat_intelligence.threatfox_client import (
    hosts_are_related,
    response_match_is_relevant,
    summarize_response,
)


def indicator(
    domain: str,
):
    return {
        "indicator": domain,
        "indicator_type": "domain",
        "hostname": domain,
    }


def threatfox_match(
    ioc: str,
):
    return {
        "id": "1",
        "ioc": ioc,
        "ioc_type": "domain",
        "ioc_type_desc": "Domain IOC",
        "threat_type": "botnet_cc",
        "threat_type_desc": "Botnet C2",
        "malware": "js.clearfake",
        "malware_printable": "ClearFake",
        "confidence_level": 90,
        "first_seen": "2026-07-22 09:49:39 UTC",
        "last_seen": None,
        "reporter": "test",
        "reference": None,
        "tags": ["ClearFake"],
    }


def test_exact_domain_matches():
    assert hosts_are_related(
        "microsoft.com",
        "microsoft.com",
    )


def test_true_subdomain_matches():
    assert hosts_are_related(
        "microsoft.com",
        "login.microsoft.com",
    )

    assert hosts_are_related(
        "portal.microsoft.com",
        "microsoft.com",
    )


def test_hyphenated_impostor_does_not_match():
    assert not hosts_are_related(
        "microsoft.com",
        "m.s-microsoft.com",
    )

    assert not hosts_are_related(
        "microsoft.com",
        "microsoft-login.com",
    )

    assert not hosts_are_related(
        "microsoft.com",
        "fake-microsoft.com",
    )


def test_microsoft_false_positive_is_filtered():
    result = summarize_response(
        indicator_data=indicator(
            "microsoft.com"
        ),
        response={
            "query_status": "ok",
            "data": [
                threatfox_match(
                    "m.s-microsoft.com"
                )
            ],
        },
    )

    assert not result["matched"]
    assert result["match_count"] == 0
    assert result["ignored_match_count"] == 1
    assert (
        result["query_status"]
        == "no_exact_match"
    )


def test_exact_malicious_domain_remains_matched():
    result = summarize_response(
        indicator_data=indicator(
            "microsooft.com"
        ),
        response={
            "query_status": "ok",
            "data": [
                threatfox_match(
                    "microsooft.com"
                )
            ],
        },
    )

    assert result["matched"]
    assert result["match_count"] == 1
    assert (
        result["malware_families"]
        == ["ClearFake"]
    )


def test_malicious_subdomain_remains_matched():
    result = summarize_response(
        indicator_data=indicator(
            "example.com"
        ),
        response={
            "query_status": "ok",
            "data": [
                threatfox_match(
                    "malware.example.com"
                )
            ],
        },
    )

    assert result["matched"]


def test_response_relevance_uses_ioc_field():
    assert not response_match_is_relevant(
        indicator_data=indicator(
            "microsoft.com"
        ),
        match=threatfox_match(
            "m.s-microsoft.com"
        ),
    )
