from __future__ import annotations

from typing import Any

import dns.exception
import dns.resolver

from app.dns_intelligence.dns_lookup import (
    create_resolver,
    normalize_domain,
    text_from_txt_record,
)


COMMON_DKIM_SELECTORS = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "mail",
    "smtp",
    "dkim",
)


def check_dkim_selector(
    domain: str,
    selector: str,
) -> dict[str, Any]:
    normalized_domain = normalize_domain(
        domain
    )

    cleaned_selector = str(
        selector or ""
    ).strip().lower()

    if not cleaned_selector:
        raise ValueError(
            "A DKIM selector is required."
        )

    query_name = (
        f"{cleaned_selector}."
        f"_domainkey.{normalized_domain}"
    )

    resolver = create_resolver()

    try:
        answer = resolver.resolve(
            query_name,
            "TXT",
            raise_on_no_answer=False,
            search=False,
        )

        records = []

        if answer.rrset is not None:
            records = [
                text_from_txt_record(
                    record
                )
                for record in answer
            ]

        dkim_records = [
            record
            for record in records
            if (
                "v=dkim1" in record.lower()
                or "p=" in record.lower()
            )
        ]

        return {
            "domain": normalized_domain,
            "selector": cleaned_selector,
            "query_name": query_name,
            "found": bool(
                dkim_records
            ),
            "records": dkim_records,
            "error": None,
        }

    except dns.resolver.NXDOMAIN:
        return {
            "domain": normalized_domain,
            "selector": cleaned_selector,
            "query_name": query_name,
            "found": False,
            "records": [],
            "error": None,
        }

    except dns.exception.DNSException as error:
        return {
            "domain": normalized_domain,
            "selector": cleaned_selector,
            "query_name": query_name,
            "found": False,
            "records": [],
            "error": str(
                error
            ),
        }


def check_common_dkim_selectors(
    domain: str,
) -> dict[str, Any]:
    results = [
        check_dkim_selector(
            domain,
            selector,
        )
        for selector in COMMON_DKIM_SELECTORS
    ]

    found = [
        result
        for result in results
        if result[
            "found"
        ]
    ]

    return {
        "domain": normalize_domain(
            domain
        ),
        "tested_selectors": list(
            COMMON_DKIM_SELECTORS
        ),
        "found_count": len(
            found
        ),
        "found": found,
        "results": results,
        "limitation": (
            "Not finding a common selector does not mean "
            "the domain lacks DKIM. Selectors are chosen "
            "by each mail operator."
        ),
    }
