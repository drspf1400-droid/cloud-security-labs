#!/usr/bin/env python3

import json
import sys


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 network_analyzer.py <network_config.json>")
        sys.exit(1)

    config_file = sys.argv[1]

    try:
        with open(config_file, "r") as file:
            config = json.load(file)
    except FileNotFoundError:
        print(f"[ERROR] Configuration file not found: {config_file}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"[ERROR] Invalid JSON: {config_file}")
        sys.exit(1)

    findings = []

    security_groups = config.get("security_groups", [])

    for security_group in security_groups:
        group_name = security_group.get("name", "unknown")
        rules = security_group.get("rules", [])

        for rule in rules:
            protocol = rule.get("protocol")
            port = rule.get("port")
            source = rule.get("source")

            if (
                protocol == "tcp"
                and port == 22
                and source == "0.0.0.0/0"
            ):
                findings.append({
                    "id": "NET-001",
                    "title": "Open SSH to Internet",
                    "severity": "HIGH",
                    "category": "Network / Security Group",
                    "risk": "Unauthorized remote access",
                    "recommendation": (
                        "Restrict SSH access to trusted IP addresses "
                        "or use a secure management path"
                    ),
                    "security_group": group_name
                })

    print("[+] AWS Network Security Analyzer")
    print(f"[+] Configuration: {config_file}")
    print()

    if findings:
        for finding in findings:
            print(f"[!] Finding ID: {finding['id']}")
            print(f"    Title: {finding['title']}")
            print(f"    Severity: {finding['severity']}")
            print(f"    Category: {finding['category']}")
            print(f"    Risk: {finding['risk']}")
            print(f"    Recommendation: {finding['recommendation']}")
            print(f"    Security Group: {finding['security_group']}")
            print()

        with open(
            "aws-security-assessment/network/network-findings.json",
            "w"
        ) as file:
            json.dump(findings, file, indent=4)

        sys.exit(1)

    print("[PASS] No open SSH access from the Internet detected.")

    with open(
        "aws-security-assessment/network/network-findings.json",
        "w"
    ) as file:
        json.dump([], file, indent=4)

    sys.exit(0)


if __name__ == "__main__":
    main()
