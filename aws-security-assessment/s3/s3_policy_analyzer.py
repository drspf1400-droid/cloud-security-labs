#!/usr/bin/env python3

import json
import sys


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 s3_policy_analyzer.py <policy.json>")
        sys.exit(1)

    policy_file = sys.argv[1]

    try:
        with open(policy_file, "r") as file:
            policy = json.load(file)
    except FileNotFoundError:
        print(f"[ERROR] Policy file not found: {policy_file}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"[ERROR] Invalid JSON: {policy_file}")
        sys.exit(1)

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    findings = []

    for statement in statements:
        effect = statement.get("Effect")
        principal = statement.get("Principal")
        action = statement.get("Action")

        if effect == "Allow" and principal == "*":
            if action == "s3:GetObject" or action == "*":
                findings.append({
                    "id": "S3-001",
                    "title": "Public S3 Bucket",
                    "severity": "CRITICAL",
                    "category": "S3 / Data Exposure",
                    "risk": "Unauthorized access to S3 objects",
                    "recommendation": "Enable Block Public Access and restrict bucket policies"
                })

    print("[+] AWS S3 Policy Analyzer")
    print(f"[+] Policy: {policy_file}")
    print()

    with open("aws-security-assessment/s3/s3-findings.json", "w") as file:
        json.dump(findings, file, indent=4)

    if findings:
        for finding in findings:
            print(f"[!] Finding ID: {finding['id']}")
            print(f"    Title: {finding['title']}")
            print(f"    Severity: {finding['severity']}")
            print(f"    Category: {finding['category']}")
            print(f"    Risk: {finding['risk']}")
            print(f"    Recommendation: {finding['recommendation']}")
            print()

        sys.exit(1)

    print("[PASS] No public S3 access detected.")
    sys.exit(0)


if __name__ == "__main__":
    main()
