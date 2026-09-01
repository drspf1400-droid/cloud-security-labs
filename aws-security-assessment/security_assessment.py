#!/usr/bin/env python3

import json
import sys


FINDINGS_FILES = [
    "aws-security-assessment/iam/iam-findings.json",
    "aws-security-assessment/s3/s3-findings.json",

"aws-security-assessment/network/network-findings.json",
]

SEVERITY_PENALTY = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 10,
    "LOW": 5
}


def load_findings():
    all_findings = []

    for findings_file in FINDINGS_FILES:
        try:
            with open(findings_file, "r") as file:
                findings = json.load(file)
                all_findings.extend(findings)
        except FileNotFoundError:
            print(f"[WARNING] Findings file not found: {findings_file}")
        except json.JSONDecodeError:
            print(f"[ERROR] Invalid JSON: {findings_file}")
            sys.exit(1)

    return all_findings


def calculate_score(findings):
    score = 100

    for finding in findings:
        severity = finding.get("severity", "LOW")
        score -= SEVERITY_PENALTY.get(severity, 0)

    return max(score, 0)


def calculate_risk(findings):
    severities = [finding.get("severity", "LOW") for finding in findings]

    if "CRITICAL" in severities:
        return "CRITICAL"
    elif "HIGH" in severities:
        return "HIGH"
    elif "MEDIUM" in severities:
        return "MEDIUM"
    else:
        return "LOW"


def main():
    findings = load_findings()

    score = calculate_score(findings)
    risk = calculate_risk(findings)

    print("[+] AWS Cloud Security Assessment")
    print()
    print(f"[+] Total Findings: {len(findings)}")
    print(f"[+] Security Score: {score}/100")
    print(f"[+] Risk Level: {risk}")
    print()

    for finding in findings:
        print(
            f"[{finding['severity']}] "
            f"{finding['id']} - "
            f"{finding['title']}"
        )

    print()

    if findings:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
