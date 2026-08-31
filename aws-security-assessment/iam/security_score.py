#!/usr/bin/env python3

import json
import sys


SEVERITY_PENALTY = {
    "CRITICAL": 40,
    "HIGH": 30,
    "MEDIUM": 15,
    "LOW": 5
}


def main():
    findings_file = "aws-security-assessment/iam/iam-findings.json"

    try:
        with open(findings_file, "r") as file:
            findings = json.load(file)
    except FileNotFoundError:
        print("[ERROR] Findings file not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        print("[ERROR] Invalid findings JSON.")
        sys.exit(1)

    score = 100

    for finding in findings:
        severity = finding.get("severity", "LOW")
        score -= SEVERITY_PENALTY.get(severity, 0)

    score = max(score, 0)

    severities = [finding.get("severity", "LOW") for finding in findings]

    if "CRITICAL" in severities:
        risk = "CRITICAL"
    elif "HIGH" in severities:
        risk = "HIGH"
    elif "MEDIUM" in severities:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    print("[+] AWS IAM Security Score")
    print(f"[+] Score: {score}/100")
    print(f"[+] Risk: {risk}")


if __name__ == "__main__":
    main()
