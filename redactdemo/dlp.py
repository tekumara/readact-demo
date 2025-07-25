import argparse
import base64
import os
import secrets
import sys

import google.cloud.dlp_v2


def deidentify_with_crypto_hash(
    project_id: str,
    text: str,
    key_bytes: bytes | None = None,
    hotwords: list[str] | None = None,
    exclusions: list[str] | None = None,
) -> str:
    # NB: there is also a DlpServiceAsyncClient
    dlp = google.cloud.dlp_v2.DlpServiceClient()
    parent = f"projects/{project_id}/locations/global"

    # Specify the types of info to detect and transform
    # https://cloud.google.com/sensitive-data-protection/docs/infotypes-reference
    info_types = [
        {"name": "PERSON_NAME"},
        {"name": "EMAIL_ADDRESS"},
        {"name": "PHONE_NUMBER"},
        {"name": "CREDIT_CARD_NUMBER"},
        {"name": "ORGANIZATION_NAME"},
        {"name": "FINANCIAL_ACCOUNT_NUMBER"},
        {"name": "GEOGRAPHIC_DATA"},
    ]

    # Setup inspect_config with rules
    # TODO: use google.cloud.dlp_v2.InspectConfig
    inspect_config = {"info_types": info_types}
    rules = []

    # Add hotword rule if hotwords provided
    if hotwords:
        pattern = "|".join(hotwords)
        hotword_regex = f"(?i)({pattern})(?-i)"
        hotword_rule = {
            "hotword_regex": {"pattern": hotword_regex},
            "likelihood_adjustment": {"fixed_likelihood": google.cloud.dlp_v2.Likelihood.VERY_UNLIKELY},
            "proximity": {"window_before": 1},
        }
        rules.append({"hotword_rule": hotword_rule})

    # Add exclusion rule if exclusions provided
    if exclusions:
        pattern = "|".join(exclusions)
        exclusion_regex = f"(?i)({pattern})(?-i)"
        exclusion_rule = {
            "exclude_info_types": {"info_types": info_types},
            "matching_type": google.cloud.dlp_v2.MatchingType.MATCHING_TYPE_FULL_MATCH,
            "regex": {"pattern": exclusion_regex},
        }
        rules.append({"exclusion_rule": exclusion_rule})

    # Add rules to inspect_config if any exist
    if rules:
        inspect_config["rule_set"] = [{"info_types": info_types, "rules": rules}]  # type: ignore

    # Configure cryptographic hash transformation with unwrapped key if provided, otherwise DLP-generated key
    if key_bytes:
        # Use unwrapped key (must be 32 or 64 bytes)
        # https://cloud.google.com/sensitive-data-protection/docs/reference/rest/v2/projects.deidentifyTemplates#cryptohashconfig
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
    # https://cloud.google.com/python/docs/reference/dlp/latest/google.cloud.dlp_v2.services.dlp_service.DlpServiceAsyncClient#google_cloud_dlp_v2_services_dlp_service_DlpServiceAsyncClient_deidentify_content
    response = dlp.deidentify_content(
        request={
            "parent": parent,
            "deidentify_config": deidentify_config,
            "inspect_config": inspect_config,
            "item": item,
        }
    )

    # Return the deidentified text
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
    parser.add_argument(
        "--store",
        "-s",
        action="store_true",
        help="Store the redacted text to a file instead of printing to stdout. "
        "The output file will have the same name as the input file with a .redact suffix.",
    )
    parser.add_argument(
        "--combined",
        "-c",
        action="store_true",
        help="Write both source and redacted content to the output file, "
        "with source wrapped in <source></source> tags and redacted content wrapped in "
        "<redacted></redacted> tags.",
    )
    parser.add_argument(
        "--hotwords",
        nargs="*",
        default=["foo", "bar"],
        help="List of hotwords that indicate no PII nearby (default: foo bar)",
    )
    parser.add_argument(
        "--exclusions",
        "-x",
        nargs="*",
        help="List of text patterns to exclude from detection",
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
    redacted_text = deidentify_with_crypto_hash(project_id, text, key_bytes, args.hotwords, args.exclusions)

    # If --store is specified and we have an input file, write to output file(s)
    if args.store and args.file:
        output_file = f"{args.file}.redact"
        try:
            # Always write the redacted text to the standard .redact file
            with open(output_file, "w") as f:
                f.write(redacted_text)
            print(f"Redacted text written to: {output_file}", file=sys.stderr)

            # If combined is specified, also write to a .redact.combined file
            if args.combined:
                combined_output_file = f"{args.file}.redact.combined"
                with open(combined_output_file, "w") as cf:
                    cf.write(f"<source>{text}</source>\n<redacted>{redacted_text}</redacted>")
                print(f"Combined text written to: {combined_output_file}", file=sys.stderr)
        except OSError as e:
            print(f"Error writing to file: {e}", file=sys.stderr)
    else:
        # Print to stdout if not storing to file
        if args.combined:
            print(f"<source>{text}</source>\n<redacted>{redacted_text}</redacted>")
        else:
            print(redacted_text)


if __name__ == "__main__":
    main()
