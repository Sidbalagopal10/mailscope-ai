import csv
import random
from pathlib import Path


OUTPUT_PATH = Path("training/demo_url_dataset.csv")

RANDOM_SEED = 42


BENIGN_DOMAINS = [
    "example.com",
    "github.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "wikipedia.org",
    "python.org",
    "stackoverflow.com",
    "cloudflare.com",
]

BENIGN_PATHS = [
    "",
    "/",
    "/about",
    "/help",
    "/docs",
    "/products",
    "/account/settings",
    "/search",
    "/support/contact",
    "/blog/security",
]

PHISHING_BRANDS = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "bank",
    "outlook",
    "office365",
]

PHISHING_ACTIONS = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "unlock",
    "confirm",
    "billing",
    "password",
]

SUSPICIOUS_TLDS = [
    "example",
    "test",
    "invalid",
]

IP_ADDRESSES = [
    "192.0.2.10",
    "198.51.100.25",
    "203.0.113.50",
    "192.0.2.175",
]


def generate_benign_urls(count: int) -> list:
    urls = []

    while len(urls) < count:
        domain = random.choice(BENIGN_DOMAINS)
        path = random.choice(BENIGN_PATHS)

        query = ""

        if path == "/search":
            query = "?q=cybersecurity"

        elif path == "/products":
            query = "?category=software"

        url = f"https://{domain}{path}{query}"
        urls.append((url, 0))

    return urls


def generate_phishing_urls(count: int) -> list:
    urls = []

    while len(urls) < count:
        brand = random.choice(PHISHING_BRANDS)
        action = random.choice(PHISHING_ACTIONS)
        second_action = random.choice(PHISHING_ACTIONS)
        tld = random.choice(SUSPICIOUS_TLDS)

        pattern = random.randint(1, 8)

        if pattern == 1:
            url = (
                f"http://{brand}-{action}-security."
                f"{tld}/{second_action}"
            )

        elif pattern == 2:
            url = (
                f"http://{brand}.{action}.account."
                f"{tld}/login"
            )

        elif pattern == 3:
            ip_address = random.choice(IP_ADDRESSES)

            url = (
                f"http://{ip_address}/{brand}/"
                f"{action}?session=938274"
            )

        elif pattern == 4:
            url = (
                f"http://secure-{brand}-{action}."
                f"{tld}:8080/{second_action}"
            )

        elif pattern == 5:
            url = (
                f"https://xn--{brand}-{action}-"
                f"9za.{tld}/{second_action}"
            )

        elif pattern == 6:
            url = (
                f"http://{brand}-{action}.{tld}/"
                f"%2F{second_action}%3Faccount"
            )

        elif pattern == 7:
            url = (
                f"http://{brand}.{action}.{second_action}."
                f"account.{tld}/signin"
            )

        else:
            url = (
                f"http://{brand}-security-alert."
                f"{tld}/{action}/password/"
                f"confirm?user=123456"
            )

        urls.append((url, 1))

    return urls


def main() -> None:
    random.seed(RANDOM_SEED)

    benign_rows = generate_benign_urls(300)
    phishing_rows = generate_phishing_urls(300)

    rows = benign_rows + phishing_rows

    random.shuffle(rows)

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_PATH.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        writer = csv.writer(csv_file)

        writer.writerow(
            [
                "url",
                "label",
            ]
        )

        writer.writerows(rows)

    print(
        f"Created {len(rows)} labeled URLs at "
        f"{OUTPUT_PATH}"
    )

    print(
        f"Benign URLs: {len(benign_rows)}"
    )

    print(
        f"Phishing URLs: {len(phishing_rows)}"
    )


if __name__ == "__main__":
    main()
