#!/usr/bin/env python3

import json
import sys
import os

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 iam_policy_analyzer.py <policy.json>")
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
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]

        if isinstance(resources, str):
            resources = [resources]

        if effect == "Allow" and "*" in actions and "*" in resources:
            findings.append({
                "id": "IAM-001",
                "title": "Excessive IAM Permissions",
                "severity": "HIGH",
                "category": "IAM / Least Privilege",
                "risk": "Privilege escalation and unauthorized access",
                "recommendation": "Apply the principle of least privilege"
            })

    print("[+] AWS IAM Policy Analyzer")
    print(f"[+] Policy: {policy_file}")
    print()


    with open("aws-security-assessment/iam/iam-findings.json", "w") as file:
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

    print("[PASS] No full wildcard permissions detected.")
    sys.exit(0)


if __name__ == "__main__":
    main()
