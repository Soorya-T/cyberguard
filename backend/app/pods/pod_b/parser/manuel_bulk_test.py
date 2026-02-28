import json
import os
from app.pods.pod_b.parser.email_parser import parse_email


def run_bulk_test():
    # Get current file directory
    current_dir = os.path.dirname(__file__)
    file_path = os.path.join(current_dir, "sample_bulk.json")

    with open(file_path, "r") as f:
        emails = json.load(f)

    print(f"\nProcessing {len(emails)} emails...\n")

    for idx, email in enumerate(emails, 1):
        parsed, error = parse_email(email, tenant_id="manual-test")

        print("=" * 50)
        print(f"Email #{idx}")

        if error:
            print("❌ Error:", error)
        else:
            print("✅ Parsed Output:")
            print(json.dumps(parsed, indent=2, default=str))


if __name__ == "__main__":
    run_bulk_test()