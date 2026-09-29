#!/usr/bin/env python3

POLICY_CATALOG = {
    "SSH-002": {
        "lab": "apply",
        "staging": "dry-run",
        "production": "dry-run",
        "requires_human_approval": True,
    },
}


def evaluate_remediation_policy(finding, environment="lab"):
    finding_id = finding.get("finding_id")

    if finding_id not in POLICY_CATALOG:
        return {
            "decision": "blocked",
            "reason": "No remediation policy exists for this finding.",
        }

    policy = POLICY_CATALOG[finding_id]

    if policy["requires_human_approval"]:
        remediation = finding.get("remediation", {})

        if finding.get("status") != "approved":
            return {
                "decision": "blocked",
                "reason": "Finding has not been approved by a human reviewer.",
            }

        if remediation.get("approval_status") != "approved":
            return {
                "decision": "blocked",
                "reason": "Remediation approval is missing.",
            }

    if environment not in policy:
        return {
            "decision": "blocked",
            "reason": f"Environment is not allowed: {environment}",
        }

    decision = policy[environment]

    return {
        "decision": decision,
        "reason": (
            f"Policy for {finding_id} allows "
            f"{decision} in {environment}."
        ),
    }
