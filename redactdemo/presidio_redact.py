import argparse
import hashlib
import sys

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# Setup Presidio NLP engine with spaCy
nlp_engine_provider = NlpEngineProvider(
    nlp_configuration={"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]}
)

# Create analyzer with the NLP engine
try:
    # Try to load the NLP engine
    nlp_engine = nlp_engine_provider.create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
    anonymizer = AnonymizerEngine()
    print("Presidio NLP engine initialized successfully.", file=sys.stderr)
except Exception as e:
    print(f"Error: Could not initialize Presidio NLP engine: {e}", file=sys.stderr)
    sys.exit(1)


# Removed regex patterns in favor of using the Presidio NLP engine

# Map from command-line entity types to Presidio entity types
ENTITY_TYPE_MAPPING = {
    "EMAIL": "EMAIL_ADDRESS",
    "PHONE": "PHONE_NUMBER",
    "CREDIT_CARD": "CREDIT_CARD",
    "SSN": "US_SSN",
    "NAME": "PERSON",
    "ADDRESS": "ADDRESS",
    "URL": "URL",
    "IP": "IP_ADDRESS",
    "DATE": "DATE_TIME",
    "NRP": "NRP",  # National/religious/political identifiers
    "LOCATION": "LOCATION",
    "BANK": "IBAN_CODE",  # Bank account info
}


def analyze_and_redact(text: str, entity_types: list[str] | None = None) -> str:
    """
    Analyzes text for PII entities and redacts them using Presidio with SpaCy NLP engine.

    Args:
        text: The text to analyze and redact
        entity_types: Optional list of entity types to look for. If None, will use all available.

    Returns:
        The redacted text with PII information replaced with tokens
    """
    try:
        # Convert entity types to Presidio format if specified
        presidio_entities = None
        if entity_types:
            presidio_entities = [ENTITY_TYPE_MAPPING[e] for e in entity_types if e in ENTITY_TYPE_MAPPING]

        # Analyze the text with Presidio
        analysis_results = analyzer.analyze(text=text, entities=presidio_entities, language="en")

        # Function to create deterministic hash for PII values
        def hash_pii(text, entity_type):
            # Create a deterministic hash of the text
            hash_obj = hashlib.sha256(text.encode())
            # Get first 8 chars of hash
            short_hash = hash_obj.hexdigest()[:8]
            # Return hash with entity type prefix
            return f"[{entity_type}:{short_hash}]"

        # Configure anonymization with hash operator
        operators = {
            "DEFAULT": OperatorConfig("custom", {"lambda": lambda x: hash_pii(x, "ENTITY")}),
            "PERSON": OperatorConfig("custom", {"lambda": lambda x: hash_pii(x, "PERSON")}),
            "EMAIL_ADDRESS": OperatorConfig("custom", {"lambda": lambda x: hash_pii(x, "EMAIL")}),
            "PHONE_NUMBER": OperatorConfig("custom", {"lambda": lambda x: hash_pii(x, "PHONE")}),
            "CREDIT_CARD": OperatorConfig("custom", {"lambda": lambda x: hash_pii(x, "CC")}),
            "US_SSN": OperatorConfig("custom", {"lambda": lambda x: hash_pii(x, "SSN")}),
            "ADDRESS": OperatorConfig("custom", {"lambda": lambda x: hash_pii(x, "ADDR")}),
            "URL": OperatorConfig("custom", {"lambda": lambda x: hash_pii(x, "URL")}),
            "IP_ADDRESS": OperatorConfig("custom", {"lambda": lambda x: hash_pii(x, "IP")}),
            "DATE_TIME": OperatorConfig("custom", {"lambda": lambda x: hash_pii(x, "DATE")}),
            "NRP": OperatorConfig("custom", {"lambda": lambda x: hash_pii(x, "NRP")}),
            "LOCATION": OperatorConfig("custom", {"lambda": lambda x: hash_pii(x, "LOC")}),
            "IBAN_CODE": OperatorConfig("custom", {"lambda": lambda x: hash_pii(x, "BANK")}),
        }

        # Anonymize detected entities
        result = anonymizer.anonymize(text=text, analyzer_results=analysis_results, operators=operators)

        return result.text

    except Exception as e:
        print(f"Error using Presidio: {e}", file=sys.stderr)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Redact sensitive information in text.")
    parser.add_argument(
        "--file",
        "-f",
        help="Path to a file containing text to redact. If not provided, a default example will be used.",
    )
    parser.add_argument(
        "--entities",
        "-e",
        nargs="+",
        choices=[
            "EMAIL",
            "PHONE",
            "CREDIT_CARD",
            "SSN",
            "NAME",
            "ADDRESS",
            "URL",
            "IP",
            "DATE",
            "NRP",
            "LOCATION",
            "BANK",
        ],
        help="Specific entity types to detect, space separated (e.g., NAME EMAIL)",
    )
    args = parser.parse_args()

    # Default text if no file is provided
    text = "My name is John Doe and my email is john.doe@example.com. My phone is 555-123-4567."

    # If a file path is provided, read from the file
    if args.file:
        try:
            with open(args.file) as f:
                text = f.read()
            print(f"Reading text from file: {args.file}", file=sys.stderr)
        except OSError as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            exit(1)

    # Redact the text
    redacted_text = analyze_and_redact(text, args.entities)
    print(redacted_text)


if __name__ == "__main__":
    main()
