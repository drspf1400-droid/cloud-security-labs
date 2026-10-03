from copy import deepcopy

from modules.security_gate import (
    EXIT_GATE_FAILED,
    EXIT_PASS,
    evaluate_security_gate,
)


def verified_report():
    return {
        "executive_summary": {
            "assurance_state": "verified",
            "trust_decision": "accept",
            "critical_findings": 0,
            "execution_outcomes": {
                "executed": 2,
                "dry_run": 0,
                "blocked": 0,
                "failed": 0,
            },
        }
    }


def test_verified_report_passes_default_gate():
    result = evaluate_security_gate(
        verified_report()
    )

    assert result["passed"] is True
    assert result["decision"] == "pass"
    assert result["exit_code"] == EXIT_PASS
    assert result["reasons"] == []


def test_attention_required_fails_gate():
    report = verified_report()

    report["executive_summary"][
        "assurance_state"
    ] = "attention_required"

    result = evaluate_security_gate(report)

    assert result["passed"] is False
    assert result["exit_code"] == EXIT_GATE_FAILED

    codes = {
        reason["code"]
        for reason in result["reasons"]
    }

    assert "GATE-ASSURANCE-STATE" in codes


def test_rejected_trust_fails_gate():
    report = verified_report()

    report["executive_summary"][
        "trust_decision"
    ] = "reject"

    result = evaluate_security_gate(report)

    codes = {
        reason["code"]
        for reason in result["reasons"]
    }

    assert result["passed"] is False
    assert "GATE-TRUST-DECISION" in codes


def test_critical_findings_fail_gate():
    report = verified_report()

    report["executive_summary"][
        "critical_findings"
    ] = 1

    result = evaluate_security_gate(report)

    codes = {
        reason["code"]
        for reason in result["reasons"]
    }

    assert result["passed"] is False
    assert "GATE-CRITICAL-FINDINGS" in codes


def test_failed_execution_fails_gate():
    report = verified_report()

    report["executive_summary"][
        "execution_outcomes"
    ]["failed"] = 1

    result = evaluate_security_gate(report)

    codes = {
        reason["code"]
        for reason in result["reasons"]
    }

    assert result["passed"] is False
    assert "GATE-FAILED-EXECUTIONS" in codes


def test_blocked_execution_fails_gate():
    report = verified_report()

    report["executive_summary"][
        "execution_outcomes"
    ]["blocked"] = 2

    result = evaluate_security_gate(report)

    codes = {
        reason["code"]
        for reason in result["reasons"]
    }

    assert result["passed"] is False
    assert "GATE-BLOCKED-EXECUTIONS" in codes


def test_custom_policy_can_allow_blocked_execution():
    report = verified_report()

    report["executive_summary"][
        "execution_outcomes"
    ]["blocked"] = 2

    policy = {
        "fail_on_assurance_states": [
            "attention_required"
        ],
        "fail_on_trust_decisions": [
            "reject"
        ],
        "max_critical_findings": 0,
        "max_failed_executions": 0,
        "max_blocked_executions": 5,
    }

    result = evaluate_security_gate(
        report,
        policy,
    )

    assert result["passed"] is True
    assert result["exit_code"] == EXIT_PASS


def test_gate_does_not_mutate_inputs():
    report = verified_report()

    policy = {
        "fail_on_assurance_states": [],
        "fail_on_trust_decisions": [],
        "max_critical_findings": 0,
        "max_failed_executions": 0,
        "max_blocked_executions": 0,
    }

    original_report = deepcopy(report)
    original_policy = deepcopy(policy)

    evaluate_security_gate(
        report,
        policy,
    )

    assert report == original_report
    assert policy == original_policy
