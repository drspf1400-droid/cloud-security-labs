#!/usr/bin/env python3

import copy
import json
import sys
from pathlib import Path


SEVERITY_RANK = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

ENGINE_NAME = "deterministic-context-baseline"
ENGINE_VERSION = "2.0"
MAX_PRIORITY_SCORE = 8


def evidence_modifiers(finding):
    evidence = finding.get("evidence", {})
    modifiers = []

    # Network socket bound to all interfaces.
    # This does NOT prove Internet exposure.
    if evidence.get("type") == "socket":
        bind_address = evidence.get("bind_address")

        if bind_address in {"0.0.0.0", "::"}:
            modifiers.append(
                ("socket_bound_all_interfaces=true", 1)
            )

        if evidence.get("internet_exposed") is True:
            modifiers.append(
                ("socket_internet_exposed=true", 1)
            )

    # SSH configuration evidence.
    if evidence.get("type") == "configuration":
        key = evidence.get("key")
        value = str(evidence.get("observed_value", "")).lower()

        if (
            key == "PermitRootLogin"
            and value in {"yes", "without-password", "prohibit-password"}
        ):
            modifiers.append(
                ("ssh_root_login_permitted=true", 1)
            )

        if (
            key == "PasswordAuthentication"
            and value == "yes"
        ):
            modifiers.append(
                ("ssh_password_authentication=true", 1)
            )

    # Firewall status evidence.
    if (
        finding.get("category") == "firewall"
        and evidence.get("type") == "command_output"
        and evidence.get("key") == "status"
        and str(evidence.get("observed_value", "")).lower() == "inactive"
    ):
        modifiers.append(
            ("host_firewall_inactive=true", 1)
        )

    # Update evidence: only increase when security relevance is explicit.
    if (
        evidence.get("type") == "package_inventory"
        and evidence.get("security_updates_confirmed") is True
    ):
        modifiers.append(
            ("security_updates_confirmed=true", 1)
        )

    return modifiers


def prioritize_finding(finding, asset):
    severity = finding["baseline_severity"]
    score = SEVERITY_RANK[severity]

    reasons = [
        f"baseline_severity={severity}"
    ]

    # Asset-level context.
    if asset.get("internet_exposed") is True:
        score += 1
        reasons.append("asset_internet_exposed=true")

    criticality = asset.get("business_criticality")
    if criticality in {"high", "critical"}:
        score += 1
        reasons.append(
            f"business_criticality={criticality}"
        )

    if asset.get("environment") == "production":
        score += 1
        reasons.append("environment=production")

    # Finding-level evidence.
    for reason, modifier in evidence_modifiers(finding):
        score += modifier
        reasons.append(reason)

    score = min(score, MAX_PRIORITY_SCORE)

    return {
        "score": score,
        "reasons": reasons,
        "engine": {
            "name": ENGINE_NAME,
            "version": ENGINE_VERSION
        }
    }


def prioritize_assessment(assessment):
    result = copy.deepcopy(assessment)
    asset = result["asset"]

    for finding in result["findings"]:
        finding["priority"] = prioritize_finding(
            finding,
            asset
        )

    result["findings"].sort(
        key=lambda finding: (
            finding["priority"]["score"],
            SEVERITY_RANK[finding["baseline_severity"]],
            finding["finding_id"],
        ),
        reverse=True,
    )

    return result


def main():
    if len(sys.argv) != 3:
        raise SystemExit(
            "Usage: prioritize.py INPUT_ASSESSMENT OUTPUT_ASSESSMENT"
        )

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    assessment = json.loads(input_path.read_text())
    prioritized = prioritize_assessment(assessment)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(prioritized, indent=2) + "\n"
    )

    for finding in prioritized["findings"]:
        priority = finding["priority"]
        print(
            f"{finding['finding_id']}: "
            f"score={priority['score']} "
            f"severity={finding['baseline_severity']} "
            f"reasons={','.join(priority['reasons'])}"
        )

    print(
        f"PRIORITIZED ASSESSMENT CREATED: {output_path}"
    )


if __name__ == "__main__":
    main()
