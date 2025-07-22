import argparse
import base64
import os
import secrets
import sys

import google.cloud.dlp_v2


def deidentify_with_crypto_hash(project_id: str, text: str, key_bytes: bytes | None = None) -> str:
    dlp = google.cloud.dlp_v2.DlpServiceClient()
    parent = f"projects/{project_id}/locations/global"

    # Specify the types of info to detect and transform
    info_types = [
        {"name": "PERSON_NAME"},
        {"name": "EMAIL_ADDRESS"},
        {"name": "PHONE_NUMBER"},
        {"name": "CREDIT_CARD_NUMBER"},
        {"name": "ORGANIZATION_NAME"},
        {"name": "FINANCIAL_ACCOUNT_NUMBER"},
    ]

    # Configuration for the DLP API
    inspect_config = {
        "info_types": info_types,
    }

    # Configure cryptographic hash transformation with unwrapped key if provided, otherwise DLP-generated key
    if key_bytes:
        # Use unwrapped key (must be 32 or 64 bytes)
        crypto_hash_config = {"crypto_key": {"unwrapped": {"key": key_bytes}}}
    else:
        # Use transient key
        crypto_hash_config = {"crypto_key": {"transient": {"name": "dlp-generated-key"}}}

    deidentify_config = {
        "info_type_transformations": {
            "transformations": [{"primitive_transformation": {"crypto_hash_config": crypto_hash_config}}]
        }
    }

    # Convert string to item
    item = {"value": text}

    # Call the DLP API
    response = dlp.deidentify_content(
        request={
            "parent": parent,
            "deidentify_config": deidentify_config,
            "inspect_config": inspect_config,
            "item": item,
        }
    )

    # Output the deidentified text
    # print(f"Original text: {text}")
    print(response.item.value)
    return response.item.value


def main() -> None:
    parser = argparse.ArgumentParser(description="Deidentify sensitive information in text.")
    parser.add_argument(
        "--file",
        "-f",
        help="Path to a file containing text to deidentify. If not provided, a default example will be used.",
    )
    parser.add_argument(
        "--key",
        "-k",
        help="Optional: Base64-encoded 32 or 64 byte key for hashing. If not provided, a transient key will be used.",
    )
    parser.add_argument(
        "--generate-key",
        "-g",
        action="store_true",
        help="Generate and print a random 32-byte key encoded as base64.",
    )
    args = parser.parse_args()

    # Generate and print a random key if requested
    if args.generate_key:
        key = secrets.token_bytes(32)  # Generate a 32-byte random key
        encoded_key = base64.b64encode(key).decode("ascii")
        print(f"Generated key (base64): {encoded_key}", file=sys.stderr)
        if not args.file and not args.key:
            # If only generating a key and not processing text, exit
            return

    project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
    assert project_id, "GOOGLE_CLOUD_PROJECT environment variable must be set."

    # Default text if no file is provided
    text = "My name is John Doe and my email is john.doe@example.com."

    # If a file path is provided, read from the file
    if args.file:
        try:
            with open(args.file) as f:
                text = f.read()
            print(f"Reading text from file: {args.file}", file=sys.stderr)
        except OSError as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            exit(1)

    # Decode the key if provided
    key_bytes = None
    if args.key:
        try:
            key_bytes = base64.b64decode(args.key)
            if len(key_bytes) not in (32, 64):
                print(f"Error: Key must be 32 or 64 bytes (got {len(key_bytes)})", file=sys.stderr)
                exit(1)
        except Exception as e:
            print(f"Error decoding key: {e}", file=sys.stderr)
            exit(1)

    # Deidentify the text
    deidentify_with_crypto_hash(project_id, text, key_bytes)


if __name__ == "__main__":
    main()
