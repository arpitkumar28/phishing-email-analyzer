import argparse
import ipaddress
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlsplit


URL_PATTERN = re.compile(r"""https?://[^\s<>"']+""", re.IGNORECASE)
TRAILING_PUNCTUATION = ".,!?;:)]}"


def get_email_body(message):
    """Return readable text from the email, excluding attachments."""
    parts = message.walk() if message.is_multipart() else [message]
    bodies = []

    for part in parts:
        if part.get_content_disposition() == "attachment":
            continue

        if part.get_content_type() != "text/plain":
            continue

        try:
            content = part.get_content()
            if isinstance(content, str):
                bodies.append(content)
        except (LookupError, UnicodeError):
            continue

    return "\n".join(bodies)


def extract_urls(body):
    """Extract HTTP and HTTPS URLs from text."""
    found = URL_PATTERN.findall(body)
    return list(dict.fromkeys(
        url.rstrip(TRAILING_PUNCTUATION) for url in found
    ))


def inspect_url(url):
    """Return simple warning signs; this does not prove a URL is malicious."""
    warnings = []

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname

        if not hostname:
            return ["Could not determine the hostname"]

        if parsed.scheme.lower() == "http":
            warnings.append("Uses unencrypted HTTP")

        if parsed.username is not None or parsed.password is not None:
            warnings.append("Contains user information before the hostname")

        try:
            ipaddress.ip_address(hostname)
            warnings.append("Uses an IP address as the hostname")
        except ValueError:
            pass

    except ValueError:
        warnings.append("Could not parse this URL")

    return warnings


def analyze_email(file_path):
    path = Path(file_path)

    if not path.is_file():
        print(f"Error: email file not found: {file_path}")
        return

    try:
        with path.open("rb") as email_file:
            message = BytesParser(
                policy=policy.default
            ).parse(email_file)
    except OSError as error:
        print(f"Error reading email: {error}")
        return

    print("\nPHISHING EMAIL ANALYZER")
    print("=" * 35)
    print(f"File: {path.name}")
    print(f"From: {message.get('From', 'Not provided')}")
    print(f"To: {message.get('To', 'Not provided')}")
    print(f"Subject: {message.get('Subject', 'Not provided')}")
    print(f"Date: {message.get('Date', 'Not provided')}")

    print("\nEMAIL HEADERS")
    print("-" * 35)
    for name, value in message.items():
        print(f"{name}: {value}")

    body = get_email_body(message)
    urls = extract_urls(body)

    print("\nURL ANALYSIS")
    print("-" * 35)

    if not urls:
        print("No HTTP/HTTPS URLs found.")
    else:
        for number, url in enumerate(urls, start=1):
            print(f"{number}. {url}")
            warnings = inspect_url(url)

            if warnings:
                for warning in warnings:
                    print(f"   WARNING: {warning}")
            else:
                print("   No configured warning signs found.")

    print("\nNote: URL warnings are clues for investigation,")
    print("not proof that a link is malicious.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract email headers and inspect URLs."
    )
    parser.add_argument("email_file", help="Path to a saved .eml file")
    args = parser.parse_args()
    analyze_email(args.email_file)
