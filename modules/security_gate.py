#!/usr/bin/env python3

from copy import deepcopy


EXIT_PASS = 0
EXIT_GATE_FAILED = 2


DEFAULT_GATE_POLICY = {
    "fail_on_assurance_states": [
        "attention_required",
    ],
    "fail_on_trust_decisions": [
        "reject",
    ],
    "max_critical_findings": 0,
    "max_failed_executions": 0,
    "max_blocked_executions": 0,
}


def evaluate_security_gate(
    report,
    policy=None,
):
    """
    Evaluate a Security Assurance Report against
    deterministic CI/CD security gate policy.

    Returns a machine-readable decision and does not
    mutate the supplied report or policy.
    """

    source = deepcopy(report)

    effective_policy = deepcopy(
        DEFAULT_GATE_POLICY
        if policy is None
        else policy
    )

    summary = source.get(
        "executive_summary",
        {},
    )

    assurance_state = summary.get(
        "assurance_state"
    )

    trust_decision = summary.get(
        "trust_decision"
    )

    critical_findings = summary.get(
        "critical_findings",
        0,
    )

    execution = summary.get(
        "execution_outcomes",
        {},
    )

    failed_executions = execution.get(
        "failed",
        0,
    )

    blocked_executions = execution.get(
        "blocked",
        0,
    )

    reasons = []

    if assurance_state in effective_policy.get(
        "fail_on_assurance_states",
        [],
    ):
        reasons.append(
            {
                "code": "GATE-ASSURANCE-STATE",
                "message": (
                    "Assurance state is not allowed "
                    f"for deployment: {assurance_state}"
                ),
            }
        )

    if trust_decision in effective_policy.get(
        "fail_on_trust_decisions",
        [],
    ):
        reasons.append(
            {
                "code": "GATE-TRUST-DECISION",
                "message": (
                    "Trust decision is not allowed: "
                    f"{trust_decision}"
                ),
            }
        )

    max_critical = effective_policy.get(
        "max_critical_findings"
    )

    if (
        max_critical is not None
        and critical_findings > max_critical
    ):
        reasons.append(
            {
                "code": "GATE-CRITICAL-FINDINGS",
                "message": (
                    "Critical finding count exceeds "
                    f"allowed maximum "
                    f"({critical_findings} > "
                    f"{max_critical})"
                ),
            }
        )

    max_failed = effective_policy.get(
        "max_failed_executions"
    )

    if (
        max_failed is not None
        and failed_executions > max_failed
    ):
        reasons.append(
            {
                "code": "GATE-FAILED-EXECUTIONS",
                "message": (
                    "Failed execution count exceeds "
                    f"allowed maximum "
                    f"({failed_executions} > "
                    f"{max_failed})"
                ),
            }
        )

    max_blocked = effective_policy.get(
        "max_blocked_executions"
    )

    if (
        max_blocked is not None
        and blocked_executions > max_blocked
    ):
        reasons.append(
            {
                "code": "GATE-BLOCKED-EXECUTIONS",
                "message": (
                    "Blocked execution count exceeds "
                    f"allowed maximum "
                    f"({blocked_executions} > "
                    f"{max_blocked})"
                ),
            }
        )

    passed = len(reasons) == 0

    return {
        "gate_version": "1.0",
        "decision": (
            "pass"
            if passed
            else "fail"
        ),
        "passed": passed,
        "exit_code": (
            EXIT_PASS
            if passed
            else EXIT_GATE_FAILED
        ),
        "policy": effective_policy,
        "observed": {
            "assurance_state": assurance_state,
            "trust_decision": trust_decision,
            "critical_findings": critical_findings,
            "failed_executions": failed_executions,
            "blocked_executions": blocked_executions,
        },
        "reasons": reasons,
    }
