from __future__ import annotations

import csv
from pathlib import Path


OUTPUT_PATH = Path(
    "training/data/"
    "accuracy_v2_examples.csv"
)


BENIGN_URLS = [
    "https://accounts.google.com/",
    "https://support.apple.com/billing",
    "https://www.bankofamerica.com/",
    "https://secure.bankofamerica.com/login/sign-in/signOnV2Screen.go",
    "https://www.chase.com/personal/credit-cards",
    "https://www.capitalone.com/credit-cards/",
    "https://online.citi.com/",
    "https://www.wellsfargo.com/",
    "https://www.americanexpress.com/",
    "https://www.linkedin.com/jobs/",
    "https://www.linkedin.com/jobs/view/123456789/",
    "https://www.indeed.com/viewjob?jk=123456",
    "https://company.wd5.myworkdayjobs.com/en-US/careers/job/analyst",
    "https://boards.greenhouse.io/example/jobs/123456",
    "https://jobs.lever.co/example/123456",
    "https://github.com/",
    "https://www.amazon.com/gp/your-account/order-history",
    "https://www.paypal.com/myaccount/summary",
    "https://mailchi.mp/example/monthly-newsletter",
    "https://example.sendgrid.net/ls/click?upn=campaign123",
    "https://click.email.linkedin.com/?qs=campaign123456789",
    "https://trk.klclick.com/ls/click?upn=marketing-campaign",
    "https://company.com/careers/application-status",
    "https://university.edu/billing/account-statement",
]


PHISHING_URLS = [
    "http://g00gle-login.example.com/verify",
    "https://gooogle-account.example.net/signin",
    "https://googIe-security.example.org/password",
    "https://appple-id.example.com/account/verify",
    "https://appleid-confirm.example.net/login",
    "https://micros0ft-support.example.org/signin",
    "https://paypa1.example.com/account/verification",
    "https://amaz0n-login.example.net/secure/update",
    "https://bankofamerica-secure.example.com/login",
    "https://chase-verification.example.net/account",
    "https://linkedin-job-offer.example.org/login",
    "https://workday-careers.example.net/verify",
    "http://203.0.113.50/account/password/verify",
    "http://198.51.100.25:8080/paypal/login",
]


def add_variants(
    urls: list[str],
    label: int,
    category: str,
) -> list[dict]:
    rows = []

    for url in urls:
        rows.append(
            {
                "url": url,
                "label": label,
                "category": category,
            }
        )

        separator = (
            "&"
            if "?" in url
            else "?"
        )

        rows.append(
            {
                "url": (
                    f"{url}{separator}"
                    "utm_source=email"
                    "&utm_medium=campaign"
                    "&utm_campaign=summer"
                ),
                "label": label,
                "category": category,
            }
        )

    return rows


rows = []

rows.extend(
    add_variants(
        BENIGN_URLS,
        0,
        "legitimate_hard_negative",
    )
)

rows.extend(
    add_variants(
        PHISHING_URLS,
        1,
        "brand_impersonation",
    )
)

OUTPUT_PATH.parent.mkdir(
    parents=True,
    exist_ok=True,
)

with OUTPUT_PATH.open(
    "w",
    newline="",
    encoding="utf-8",
) as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "url",
            "label",
            "category",
        ],
    )

    writer.writeheader()
    writer.writerows(
        rows
    )

print(
    "Accuracy V2 examples saved to:",
    OUTPUT_PATH,
)

print(
    "Rows:",
    len(rows),
)


if __name__ == "__main__":
    pass
