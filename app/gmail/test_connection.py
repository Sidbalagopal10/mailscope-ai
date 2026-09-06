from app.gmail.gmail_client import get_gmail_service


def get_header(headers: list[dict], name: str) -> str:
    for header in headers:
        if header.get("name", "").lower() == name.lower():
            return header.get("value", "")

    return ""


def main() -> None:
    service = get_gmail_service()

    profile = (
        service.users()
        .getProfile(userId="me")
        .execute()
    )

    print("\nGmail connection successful")
    print(f"Connected account: {profile.get('emailAddress')}")
    print(f"Total messages: {profile.get('messagesTotal')}")
    print("\nRecent messages:\n")

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

    for index, message in enumerate(messages, start=1):
        details = (
            service.users()
            .messages()
            .get(
                userId="me",
                id=message["id"],
                format="metadata",
                metadataHeaders=[
                    "From",
                    "Subject",
                    "Date",
                ],
            )
            .execute()
        )

        headers = details.get("payload", {}).get("headers", [])

        print(f"{index}. {get_header(headers, 'Subject') or '(No subject)'}")
        print(f"   From: {get_header(headers, 'From') or '(Unknown sender)'}")
        print(f"   Date: {get_header(headers, 'Date') or '(Unknown date)'}")
        print()


if __name__ == "__main__":
    main()
