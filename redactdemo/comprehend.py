import argparse
import sys

import boto3

comprehend = boto3.client("comprehend")


def remove_pii(text: str) -> str:
    import base64
    import hashlib

    response = comprehend.detect_pii_entities(Text=text, LanguageCode="en")
    pii_entities = response["Entities"]
    # To avoid offset shifting, replace entities from end to start
    redacted_text = text
    entities_sorted = sorted(pii_entities, key=lambda e: e["BeginOffset"], reverse=True)
    for entity in entities_sorted:
        start_offset = entity["BeginOffset"]
        end_offset = entity["EndOffset"]
        text_to_hash = redacted_text[start_offset:end_offset]
        digest = hashlib.sha256(text_to_hash.encode()).digest()
        hashed = base64.urlsafe_b64encode(digest).decode()
        redacted_text = redacted_text[:start_offset] + hashed + redacted_text[end_offset:]

    return redacted_text


def main() -> None:
    parser = argparse.ArgumentParser(description="Deidentify sensitive information in text.")
    parser.add_argument(
        "--file",
        "-f",
        help="Path to a file containing text to deidentify. If not provided, a default example will be used.",
    )
    parser.add_argument(
        "--store",
        "-s",
        action="store_true",
        help="Store the redacted text to a file instead of printing to stdout. "
        "The output file will have the same name as the input file with a .redactc suffix.",
    )
    parser.add_argument(
        "--combined",
        "-c",
        action="store_true",
        help="Write both source and redacted content to the output file, "
        "with source wrapped in <source></source> tags and redacted content wrapped in "
        "<redacted></redacted> tags.",
    )
    args = parser.parse_args()

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
    redacted_text = remove_pii(text)

    # If --store is specified and we have an input file, write to output file(s)
    if args.store and args.file:
        output_file = f"{args.file}.redactc"
        try:
            # Always write the redacted text to the standard .redactc file
            with open(output_file, "w") as f:
                f.write(redacted_text)
            print(f"Redacted text written to: {output_file}", file=sys.stderr)

            # If combined is specified, also write to a .redactc.combined file
            if args.combined:
                combined_output_file = f"{args.file}.redactc.combined"
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
