import argparse
import os
import sys
import re
from typing import Dict, List, Optional, Pattern, Tuple

# Simple patterns for PII detection instead of using full Presidio
# which requires downloading language models


# Define patterns for common PII types
PII_PATTERNS: Dict[str, Tuple[Pattern, str]] = {
    "EMAIL": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "[EMAIL]"),
    "PHONE": (re.compile(r"\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"), "[PHONE]"),
    "CREDIT_CARD": (re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"), "[CREDIT_CARD]"),
    "SSN": (re.compile(r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b"), "[SSN]"),
    "NAME": (re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b"), "[PERSON]"),  # Simple name pattern
    "ADDRESS": (re.compile(r"\b\d+\s[A-Za-z]+\s[A-Za-z]+\.?,?\s[A-Za-z]+,?\s[A-Z]{2}\s\d{5}\b"), "[ADDRESS]"),
    "URL": (re.compile(r"https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)"), "[URL]"),
    "IP": (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP_ADDRESS]"),
}


def analyze_and_redact(text: str, entity_types: Optional[List[str]] = None) -> str:
    """
    Analyzes text for PII entities and redacts them using regex patterns.
    
    Args:
        text: The text to analyze and redact
        entity_types: Optional list of entity types to look for. If None, will use all patterns.
        
    Returns:
        The redacted text with PII information replaced with tokens
    """
    redacted_text = text
    
    # Filter patterns based on entity_types if provided
    patterns_to_use = PII_PATTERNS
    if entity_types:
        patterns_to_use = {k: v for k, v in PII_PATTERNS.items() if k in entity_types}
    
    # Apply each pattern and replace matches
    for entity_type, (pattern, replacement) in patterns_to_use.items():
        redacted_text = pattern.sub(replacement, redacted_text)
    
    return redacted_text


def main() -> None:
    parser = argparse.ArgumentParser(description="Redact sensitive information in text.")
    parser.add_argument(
        "--file", 
        "-f",
        help="Path to a file containing text to redact. If not provided, a default example will be used."
    )
    parser.add_argument(
        "--entities",
        "-e",
        nargs="+",
        choices=["EMAIL", "PHONE", "CREDIT_CARD", "SSN", "NAME", "ADDRESS", "URL", "IP"],
        help="Specific entity types to detect, space separated (e.g., NAME EMAIL)"
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