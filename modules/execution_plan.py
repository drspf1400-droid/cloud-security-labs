#!/usr/bin/env python3

from copy import deepcopy

try:
    from modules.remediation_policy import (
        evaluate_remediation_policy,
    )
    from modules.remediation import REMEDIATION_CATALOG
except ModuleNotFoundError:
    from remediation_policy import (
        evaluate_remediation_policy,
    )
    from remediation import REMEDIATION_CATALOG


def resolve_environment(assessment, environment=None):
    if environment is not None:
        return environment

    return (
        assessment
        .get("asset", {})
        .get("environment", "unknown")
    )


def build_execution_plan(
    assessment,
    environment=None,
):
    """
    Build a non-destructive remediation execution plan.

    Policy decides whether remediation is allowed.
    The execution layer also verifies that an
    implementation exists before allowing apply.
    """
    source = deepcopy(assessment)

    environment = resolve_environment(
        source,
        environment=environment,
    )

    plan = []

    summary = {
        "apply": 0,
        "dry_run": 0,
        "blocked": 0,
    }

    for finding in source.get("findings", []):
        finding_id = finding.get("finding_id")

        policy_result = evaluate_remediation_policy(
            finding,
            environment=environment,
        )

        policy_decision = policy_result["decision"]

        remediation_definition = (
            REMEDIATION_CATALOG.get(finding_id)
        )

        action = None
        if remediation_definition:
            action = remediation_definition.get("action")

        execution_decision = policy_decision
        reason = policy_result["reason"]

        # Fail closed:
        # policy approval alone is not enough.
        # An implemented remediation action must exist.
        if (
            policy_decision in {"apply", "dry-run"}
            and not action
        ):
            execution_decision = "blocked"
            reason = (
                "Policy permits remediation, but no "
                "implemented remediation action exists."
            )

        summary_key = (
            "dry_run"
            if execution_decision == "dry-run"
            else execution_decision
        )

        if summary_key not in summary:
            summary_key = "blocked"
            execution_decision = "blocked"

        summary[summary_key] += 1

        plan.append({
            "finding_id": finding_id,
            "policy_decision": policy_decision,
            "execution_decision": execution_decision,
            "action": action,
            "reason": reason,
        })

    return {
        "environment": environment,
        "summary": summary,
        "execution_plan": plan,
    }


def attach_execution_plan(
    assessment,
    environment=None,
):
    """
    Return a copy of the assessment enriched with
    a structured remediation execution plan.
    """
    result = deepcopy(assessment)

    plan = build_execution_plan(
        result,
        environment=environment,
    )

    result.setdefault("assessment", {})["execution_plan"] = {
        "environment": plan["environment"],
        "summary": plan["summary"],
        "items": plan["execution_plan"],
    }

    return result
