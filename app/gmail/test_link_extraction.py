from app.gmail.email_parser import extract_urls_from_message
from app.gmail.gmail_client import get_gmail_service


def get_header(headers: list[dict], name: str) -> str:
    for header in headers:
        if header.get("name", "").lower() == name.lower():
            return header.get("value", "")

    return ""


def main() -> None:
    service = get_gmail_service()

    response = (
        service.users()
        .messages()
        .list(
            userId="me",
            maxResults=5,
        )
        .execute()
    )

    messages = response.get("messages", [])

    if not messages:
        print("No messages found.")
        return

    for index, message_reference in enumerate(messages, start=1):
        message = (
            service.users()
            .messages()
            .get(
                userId="me",
                id=message_reference["id"],
                format="full",
            )
            .execute()
        )

        payload = message.get("payload", {})
        headers = payload.get("headers", [])

        subject = get_header(headers, "Subject") or "(No subject)"
        sender = get_header(headers, "From") or "(Unknown sender)"
        urls = extract_urls_from_message(payload)

        print("\n" + "=" * 70)
        print(f"EMAIL {index}")
        print(f"Subject: {subject}")
        print(f"From: {sender}")
        print(f"Links found: {len(urls)}")

        if not urls:
            print("No HTTP or HTTPS links found.")
            continue

        for url_index, url in enumerate(urls[:20], start=1):
            print(f"{url_index}. {url}")

        if len(urls) > 20:
            print(f"...and {len(urls) - 20} more links")


if __name__ == "__main__":
    main()
