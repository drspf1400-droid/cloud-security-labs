#!/usr/bin/env python3

from copy import deepcopy
from datetime import datetime, timezone

try:
    from modules.execution_plan import build_execution_plan
    from modules.execution_evidence import (
        build_execution_evidence,
    )
    from modules.remediation import (
        safe_apply_ssh_root_login_remediation,
    )
except ModuleNotFoundError:
    from execution_plan import build_execution_plan
    from execution_evidence import (
        build_execution_evidence,
    )
    from remediation import (
        safe_apply_ssh_root_login_remediation,
    )



def utc_now():
    return datetime.now(timezone.utc).isoformat()


def build_execution_audit_entry(
    *,
    actor,
    finding_id,
    decision,
    action,
    status,
    reason,
):
    return {
        "timestamp": utc_now(),
        "actor": actor,
        "finding_id": finding_id,
        "decision": decision,
        "action": action,
        "status": status,
        "reason": reason,
    }


ACTION_EXECUTORS = {
    "disable_ssh_root_login":
        safe_apply_ssh_root_login_remediation,
}


def execute_assessment_plan(
    assessment,
    actor,
    environment=None,
    execution_context=None,
    run_id=None,
    evidence_timestamp=None,
):
    """
    Execute an assessment remediation plan safely.

    Rules:
    - apply -> execute only when implementation
      and required context exist
    - dry-run -> never modify target
    - blocked -> never execute
    - input assessment is not mutated
    """
    result_assessment = deepcopy(assessment)
    execution_context = execution_context or {}

    plan = build_execution_plan(
        result_assessment,
        environment=environment,
    )

    findings = {
        finding.get("finding_id"): finding
        for finding in result_assessment.get(
            "findings",
            [],
        )
    }

    results = []
    audit_trail = []

    summary = {
        "executed": 0,
        "dry_run": 0,
        "blocked": 0,
        "failed": 0,
    }

    for item in plan["execution_plan"]:
        finding_id = item["finding_id"]
        decision = item["execution_decision"]
        action = item["action"]

        execution_result = {
            "finding_id": finding_id,
            "decision": decision,
            "action": action,
            "status": None,
            "reason": item["reason"],
        }

        if decision == "blocked":
            execution_result["status"] = "blocked"
            summary["blocked"] += 1
            results.append(execution_result)
            continue

        if decision == "dry-run":
            execution_result["status"] = "dry-run"
            summary["dry_run"] += 1
            results.append(execution_result)
            continue

        if decision != "apply":
            execution_result["status"] = "blocked"
            execution_result["reason"] = (
                "Unsupported execution decision."
            )
            summary["blocked"] += 1
            results.append(execution_result)
            continue

        executor = ACTION_EXECUTORS.get(action)

        if executor is None:
            execution_result["status"] = "blocked"
            execution_result["reason"] = (
                "No execution implementation exists "
                "for this action."
            )
            summary["blocked"] += 1
            results.append(execution_result)
            continue

        finding = findings.get(finding_id)

        if finding is None:
            execution_result["status"] = "blocked"
            execution_result["reason"] = (
                "Finding is missing from assessment."
            )
            summary["blocked"] += 1
            results.append(execution_result)
            continue

        context = execution_context.get(
            finding_id,
            {},
        )

        config_path = context.get("config_path")

        if action == "disable_ssh_root_login":
            if config_path is None:
                execution_result["status"] = "blocked"
                execution_result["reason"] = (
                    "Required execution context "
                    "config_path is missing."
                )
                summary["blocked"] += 1
                results.append(execution_result)
                continue

        try:
            executor(
                finding,
                config_path=config_path,
                actor=actor,
                environment=plan["environment"],
            )

            execution_result["status"] = "executed"
            execution_result["reason"] = (
                "Remediation executed and verified."
            )
            summary["executed"] += 1

        except Exception as exc:
            execution_result["status"] = "failed"
            execution_result["reason"] = str(exc)
            summary["failed"] += 1

        results.append(execution_result)

    for execution_result in results:
        audit_trail.append(
            build_execution_audit_entry(
                actor=actor,
                finding_id=execution_result["finding_id"],
                decision=execution_result["decision"],
                action=execution_result["action"],
                status=execution_result["status"],
                reason=execution_result["reason"],
            )
        )

    result_assessment.setdefault(
        "assessment",
        {},
    )["execution"] = {
        "environment": plan["environment"],
        "summary": deepcopy(summary),
        "results": deepcopy(results),
        "audit_trail": deepcopy(audit_trail),
    }

    engine_result = {
        "environment": plan["environment"],
        "summary": summary,
        "results": results,
        "audit_trail": audit_trail,
        "assessment": result_assessment,
    }

    manifest = build_execution_evidence(
        engine_result,
        actor=actor,
        run_id=run_id,
        timestamp=evidence_timestamp,
    )

    result_assessment.setdefault(
        "assessment",
        {},
    )["execution_evidence"] = deepcopy(
        manifest
    )

    engine_result["evidence_manifest"] = manifest

    return engine_result
