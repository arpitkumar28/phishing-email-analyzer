import argparse
from email import policy
from email.parser import BytesParser
from pathlib import Path


def analyze_email(file_path):
    path = Path(file_path)

    if not path.is_file():
        print(f"Error: email file not found: {file_path}")
        return

    try:
        with path.open("rb") as email_file:
            message = BytesParser(policy=policy.default).parse(email_file)
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract headers from a saved email file."
    )
    parser.add_argument("email_file", help="Path to a saved .eml file")
    args = parser.parse_args()

    analyze_email(args.email_file)
