import os
from google.cloud import dlp_v2

def inspect_string(project_id, text):
    # Initialize DLP client
    dlp = dlp_v2.DlpServiceClient()
    parent = f"projects/{project_id}/locations/global"

    # Specify the types of info to detect
    info_types = [
        {"name": "PERSON_NAME"},
        {"name": "EMAIL_ADDRESS"},
        {"name": "PHONE_NUMBER"},
        {"name": "CREDIT_CARD_NUMBER"},
    ]

    # Configuration for the DLP API
    inspect_config = {
        "info_types": info_types,
        "include_quote": True,
    }

    # The item to inspect
    item = {"value": text}

    # Call the DLP API
    response = dlp.inspect_content(
        request={
            "parent": parent,
            "inspect_config": inspect_config,
            "item": item,
        }
    )

    # Output the findings
    if response.result.findings:
        for finding in response.result.findings:
            print(
                f"Found {finding.info_type.name}: {finding.quote} "
                f"(Likelihood: {finding.likelihood})"
            )
    else:
        print("No sensitive data found.")

project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
# Example usage
inspect_string(project_id, "My name is John Doe and my email is john.doe@example.com.")
