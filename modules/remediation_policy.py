#!/usr/bin/env python3

from copy import deepcopy

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


def evaluate_assessment_policy(
    assessment,
    environment="lab",
):
    decisions = []

    summary = {
        "apply": 0,
        "dry_run": 0,
        "blocked": 0,
    }

    for finding in assessment.get("findings", []):
        result = evaluate_remediation_policy(
            finding,
            environment=environment,
        )

        decision = result["decision"]

        normalized_decision = (
            "dry_run"
            if decision == "dry-run"
            else decision
        )

        if normalized_decision not in summary:
            normalized_decision = "blocked"

        summary[normalized_decision] += 1

        decisions.append({
            "finding_id": finding.get("finding_id"),
            "decision": decision,
            "reason": result["reason"],
        })

    return {
        "environment": environment,
        "policy_summary": summary,
        "decisions": decisions,
    }


def attach_assessment_policy(
    assessment,
    environment=None,
):
    """
    Return a copy of an assessment enriched with
    remediation-policy summary information.
    """
    result = deepcopy(assessment)

    if environment is None:
        environment = (
            result.get("asset", {})
            .get("environment", "unknown")
        )

    evaluation = evaluate_assessment_policy(
        result,
        environment=environment,
    )

    result["assessment"]["remediation_policy"] = {
        "environment": evaluation["environment"],
        "summary": evaluation["policy_summary"],
    }

    return result
