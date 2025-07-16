import base64
import os

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
    ]

    # Configuration for the DLP API
    inspect_config = {
        "info_types": info_types,
    }

    # Configure deterministic encryption transformation with DLP-generated key
    crypto_deterministic_config = {
        "crypto_key": {
            "transient": {
                "name": "dlp-generated-key"
            }
        },
        "surrogate_info_type": {
            "name": "TOKEN"
        }
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
    print(f"Original text: {text}")
    print(f"Deidentified text: {response.item.value}")
    return response.item.value


def main() -> None:
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
    assert project_id, "GOOGLE_CLOUD_PROJECT environment variable must be set."

    # Example usage with DLP-generated key
    deidentify_with_generated_key(
        project_id, "My name is John Doe and my email is john.doe@example.com."
    )


if __name__ == "__main__":
    main()
