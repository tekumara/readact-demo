import base64
import os

import google.cloud.dlp_v2


def deidentify_aes_siv(project_id: str, text: str, key_name: str, wrapped_key_base64: str) -> str:
    dlp = google.cloud.dlp_v2.DlpServiceClient()
    parent = f"projects/{project_id}/locations/global"

    # The wrapped key is base64-encoded, but the library expects a binary
    # string, so decode it here.
    wrapped_key = base64.b64decode(wrapped_key_base64)

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

    # Configure AES-SIV encryption transformation
    crypto_replace_ffx_fpe_config = {
        "crypto_key": {
            "kms_wrapped": {
                "wrapped_key": wrapped_key,
                "crypto_key_name": key_name,
            }
        },
        "alphabet": "ALPHA_NUMERIC",
    }

    deidentify_config = {
        "info_type_transformations": {
            "transformations": [
                {"primitive_transformation": {"crypto_replace_ffx_fpe_config": crypto_replace_ffx_fpe_config}}
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
    # You'll need to provide your KMS key name and wrapped key
    key_name = "projects/YOUR_PROJECT/locations/YOUR_LOCATION/keyRings/YOUR_KEYRING/cryptoKeys/YOUR_KEY"
    wrapped_key = "YOUR_WRAPPED_KEY_BYTES"

    # Example usage
    deidentify_aes_siv(
        project_id, "My name is John Doe and my email is john.doe@example.com.", key_name, wrapped_key
    )


if __name__ == "__main__":
    main()
