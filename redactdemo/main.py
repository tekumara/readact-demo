import argparse
import os
import sys

import google.cloud.dlp_v2


def deidentify_with_generated_key(project_id: str, text: str) -> str:
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

    # Configure deterministic encryption transformation with DLP-generated key
    crypto_deterministic_config = {
        "crypto_key": {"transient": {"name": "dlp-generated-key"}},
        # prefix for replacement tokens
        "surrogate_info_type": {"name": "TOKEN"},
    }

    deidentify_config = {
        "info_type_transformations": {
            "transformations": [
                {"primitive_transformation": {"crypto_deterministic_config": crypto_deterministic_config}}
            ]
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
    #print(f"Original text: {text}")
    print(response.item.value)
    return response.item.value


def main() -> None:
    parser = argparse.ArgumentParser(description="Deidentify sensitive information in text.")
    parser.add_argument(
        "--file",
        "-f",
        help="Path to a file containing text to deidentify. If not provided, a default example will be used.",
    )
    args = parser.parse_args()

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

    # Deidentify the text
    deidentify_with_generated_key(project_id, text)


if __name__ == "__main__":
    main()
