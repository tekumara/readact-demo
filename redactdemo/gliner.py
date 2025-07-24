import argparse
import hashlib
import sys
from typing import cast

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import GLiNERRecognizer
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from presidio_anonymizer.entities.engine.recognizer_result import RecognizerResult as AnonymizerRecognizerResult

# Load a small spaCy model as we don't need spaCy's NER
nlp_engine = NlpEngineProvider(
    nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }
)

# Create an anonymizer engine
anonymizer = AnonymizerEngine()

# Create an analyzer engine
analyzer_engine = AnalyzerEngine()


gliner_recognizer = GLiNERRecognizer(
    model_name="urchade/gliner_multi_pii-v1",
    supported_entities=["PERSON", "ORGANIZATION", "LOCATION"],
    flat_ner=False,
    multi_label=True,
    map_location="cpu",
)

# Add the GLiNER recognizer to the registry
analyzer_engine.registry.add_recognizer(gliner_recognizer)

# Remove the spaCy recognizer to avoid NER coming from spaCy
analyzer_engine.registry.remove_recognizer("SpacyRecognizer")

print("GLiNER initialized successfully.", file=sys.stderr)


def hash_pii(text: str, entity_type: str) -> str:
    """Create a deterministic hash for PII values."""
    # Create a deterministic hash of the text
    hash_obj = hashlib.sha256(text.encode())
    # Get first 8 chars of hash
    short_hash = hash_obj.hexdigest()[:8]
    # Return hash with entity type prefix
    return f"[{entity_type}:{short_hash}]"


def analyze_and_anonymize(text: str) -> str:
    """Analyze text using GLiNER and anonymize detected entities."""
    try:
        # Analyze the text
        analysis_results = analyzer_engine.analyze(text=text, language="en")

        # Configure anonymization with hash operator
        operators = {
            "DEFAULT": OperatorConfig("custom", {"lambda": lambda x: hash_pii(x, "DEFAULT")}),
            "PERSON": OperatorConfig("custom", {"lambda": lambda x: hash_pii(x, "PERSON")}),
            "ORGANIZATION": OperatorConfig("custom", {"lambda": lambda x: hash_pii(x, "ORG")}),
            "LOCATION": OperatorConfig("custom", {"lambda": lambda x: hash_pii(x, "LOC")}),
        }

        # Anonymize detected entities
        # Cast to the anonymizer's RecognizerResult type to fix type compatibility issues
        # This cast is safe because the structure is compatible even though the types are from different modules
        anonymizer_results = cast(list[AnonymizerRecognizerResult], analysis_results)
        result = anonymizer.anonymize(text=text, analyzer_results=anonymizer_results, operators=operators)

        return result.text

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Redact sensitive information using GLiNER.")
    parser.add_argument(
        "--file",
        "-f",
        help="Path to a file containing text to redact. If not provided, a default example will be used.",
    )
    args = parser.parse_args()

    # Default text if no file is provided
    text = "Hello, my name is Rafi More, I'm from Binyamina and I work at Microsoft."

    # If a file path is provided, read from the file
    if args.file:
        try:
            with open(args.file) as f:
                text = f.read()
            print(f"Reading text from file: {args.file}", file=sys.stderr)
        except OSError as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)

    # Anonymize the text
    anonymized_text = analyze_and_anonymize(text)
    print(anonymized_text)


if __name__ == "__main__":
    main()
