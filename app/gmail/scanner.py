import argparse

from app.database.database import SessionLocal
from app.gmail.email_parser import extract_urls_from_message
from app.gmail.gmail_client import get_gmail_service
from app.gmail.url_filter import clean_urls
from app.services.risk_engine import analyze_url
from app.services.scan_service import (
    gmail_scan_exists,
    save_scan_result,
)


def get_header(
    headers: list,
    name: str,
) -> str:
    for header in headers:
        if header.get("name", "").lower() == name.lower():
            return header.get("value", "")

    return ""


def scan_recent_emails(
    max_messages: int = 5,
) -> dict:
    service = get_gmail_service()
    database = SessionLocal()

    emails_scanned = 0
    urls_found = 0
    urls_saved = 0
    duplicate_urls_skipped = 0
    suspicious_urls = 0

    try:
        response = (
            service.users()
            .messages()
            .list(
                userId="me",
                maxResults=max_messages,
            )
            .execute()
        )

        messages = response.get("messages", [])

        for message_reference in messages:
            gmail_message_id = message_reference["id"]

            message = (
                service.users()
                .messages()
                .get(
                    userId="me",
                    id=gmail_message_id,
                    format="full",
                )
                .execute()
            )

            payload = message.get("payload", {})
            headers = payload.get("headers", [])

            subject = (
                get_header(headers, "Subject")
                or "(No subject)"
            )

            sender = (
                get_header(headers, "From")
                or "(Unknown sender)"
            )

            extracted_urls = extract_urls_from_message(payload)
            cleaned_urls = clean_urls(extracted_urls)

            emails_scanned += 1
            urls_found += len(cleaned_urls)

            print("\n" + "=" * 70)
            print(f"Subject: {subject}")
            print(f"From: {sender}")
            print(f"Gmail message ID: {gmail_message_id}")
            print(f"URLs discovered: {len(cleaned_urls)}")

            if not cleaned_urls:
                print("No HTTP or HTTPS URLs found.")
                continue

            for url in cleaned_urls:
                if gmail_scan_exists(
                    database=database,
                    gmail_message_id=gmail_message_id,
                    url=url,
                ):
                    duplicate_urls_skipped += 1
                    print(f"[SKIPPED] Already scanned: {url}")
                    continue

                result = analyze_url(url)

                record = save_scan_result(
                    database=database,
                    result=result,
                    source="gmail",
                    gmail_message_id=gmail_message_id,
                    email_subject=subject,
                    email_sender=sender,
                )

                urls_saved += 1

                if result.is_suspicious:
                    suspicious_urls += 1

                print(
                    f"[{result.risk_level}] "
                    f"{result.severity}/10 "
                    f"{url}"
                )

                if result.reasons:
                    for reason in result.reasons:
                        print(f"  - {reason}")
                else:
                    print("  - No suspicious indicators detected")

                print(f"  Saved as scan ID: {record.id}")

        return {
            "emails_scanned": emails_scanned,
            "urls_found": urls_found,
            "urls_saved": urls_saved,
            "duplicate_urls_skipped": duplicate_urls_skipped,
            "suspicious_urls": suspicious_urls,
        }

    finally:
        database.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan recent Gmail messages for suspicious URLs."
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Number of recent Gmail messages to scan.",
    )

    arguments = parser.parse_args()

    if arguments.limit < 1:
        parser.error("--limit must be at least 1")

    if arguments.limit > 100:
        parser.error("--limit cannot exceed 100")

    print(
        "Starting Gmail phishing scan for "
        f"{arguments.limit} recent emails..."
    )

    summary = scan_recent_emails(
        max_messages=arguments.limit
    )

    print("\n" + "=" * 70)
    print("SCAN COMPLETE")
    print(f"Emails scanned: {summary['emails_scanned']}")
    print(f"URLs discovered: {summary['urls_found']}")
    print(f"New results saved: {summary['urls_saved']}")
    print(
        "Duplicate URLs skipped: "
        f"{summary['duplicate_urls_skipped']}"
    )
    print(
        "New suspicious URLs: "
        f"{summary['suspicious_urls']}"
    )


if __name__ == "__main__":
    main()
