import importlib.util
from copy import deepcopy
from pathlib import Path


MODULE_PATH = Path("modules/execution_plan.py")

spec = importlib.util.spec_from_file_location(
    "execution_plan",
    MODULE_PATH,
)

plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


def approved_ssh_finding():
    return {
        "finding_id": "SSH-002",
        "status": "approved",
        "remediation": {
            "approval_status": "approved",
            "applied": False,
        },
    }


def unknown_finding():
    return {
        "finding_id": "UNKNOWN-001",
        "status": "approved",
        "remediation": {
            "approval_status": "approved",
            "applied": False,
        },
    }


def test_lab_plan_allows_supported_remediation():
    assessment = {
        "asset": {
            "environment": "lab",
        },
        "findings": [
            approved_ssh_finding(),
        ],
    }

    result = plan.build_execution_plan(assessment)

    assert result["environment"] == "lab"

    assert result["summary"] == {
        "apply": 1,
        "dry_run": 0,
        "blocked": 0,
    }

    item = result["execution_plan"][0]

    assert item["finding_id"] == "SSH-002"
    assert item["policy_decision"] == "apply"
    assert item["execution_decision"] == "apply"
    assert item["action"] == "disable_ssh_root_login"


def test_production_plan_is_dry_run():
    assessment = {
        "asset": {
            "environment": "production",
        },
        "findings": [
            approved_ssh_finding(),
        ],
    }

    result = plan.build_execution_plan(assessment)

    assert result["summary"] == {
        "apply": 0,
        "dry_run": 1,
        "blocked": 0,
    }

    item = result["execution_plan"][0]

    assert item["policy_decision"] == "dry-run"
    assert item["execution_decision"] == "dry-run"
    assert item["action"] == "disable_ssh_root_login"


def test_unknown_finding_is_blocked():
    assessment = {
        "asset": {
            "environment": "lab",
        },
        "findings": [
            unknown_finding(),
        ],
    }

    result = plan.build_execution_plan(assessment)

    assert result["summary"] == {
        "apply": 0,
        "dry_run": 0,
        "blocked": 1,
    }

    item = result["execution_plan"][0]

    assert item["execution_decision"] == "blocked"
    assert item["action"] is None


def test_explicit_environment_overrides_asset():
    assessment = {
        "asset": {
            "environment": "lab",
        },
        "findings": [
            approved_ssh_finding(),
        ],
    }

    result = plan.build_execution_plan(
        assessment,
        environment="production",
    )

    assert result["environment"] == "production"
    assert result["summary"]["dry_run"] == 1


def test_execution_plan_does_not_mutate_input():
    assessment = {
        "asset": {
            "environment": "lab",
        },
        "findings": [
            approved_ssh_finding(),
        ],
    }

    original = deepcopy(assessment)

    plan.build_execution_plan(assessment)

    assert assessment == original


def test_empty_assessment_returns_empty_plan():
    assessment = {
        "asset": {
            "environment": "lab",
        },
        "findings": [],
    }

    result = plan.build_execution_plan(assessment)

    assert result["summary"] == {
        "apply": 0,
        "dry_run": 0,
        "blocked": 0,
    }

    assert result["execution_plan"] == []


def test_execution_plan_can_be_attached_to_assessment():
    assessment = {
        "assessment": {
            "assessment_id": "ASM-001",
        },
        "asset": {
            "environment": "lab",
        },
        "findings": [
            approved_ssh_finding(),
            unknown_finding(),
        ],
    }

    original = deepcopy(assessment)

    result = plan.attach_execution_plan(
        assessment
    )

    assert assessment == original

    attached = result["assessment"]["execution_plan"]

    assert attached["environment"] == "lab"

    assert attached["summary"] == {
        "apply": 1,
        "dry_run": 0,
        "blocked": 1,
    }

    assert len(attached["items"]) == 2


def test_attached_plan_respects_explicit_environment():
    assessment = {
        "assessment": {
            "assessment_id": "ASM-001",
        },
        "asset": {
            "environment": "lab",
        },
        "findings": [
            approved_ssh_finding(),
        ],
    }

    result = plan.attach_execution_plan(
        assessment,
        environment="production",
    )

    attached = result["assessment"]["execution_plan"]

    assert attached["environment"] == "production"

    assert attached["summary"] == {
        "apply": 0,
        "dry_run": 1,
        "blocked": 0,
    }


def test_execution_layer_fails_closed_without_action():
    original_evaluator = plan.evaluate_remediation_policy

    try:
        plan.evaluate_remediation_policy = (
            lambda finding, environment="lab": {
                "decision": "apply",
                "reason": "Policy allows apply.",
            }
        )

        assessment = {
            "asset": {
                "environment": "lab",
            },
            "findings": [
                {
                    "finding_id": "NO-IMPLEMENTATION",
                    "status": "approved",
                    "remediation": {
                        "approval_status": "approved",
                    },
                }
            ],
        }

        result = plan.build_execution_plan(
            assessment
        )

        item = result["execution_plan"][0]

        assert item["policy_decision"] == "apply"
        assert item["execution_decision"] == "blocked"
        assert item["action"] is None
        assert result["summary"]["blocked"] == 1

    finally:
        plan.evaluate_remediation_policy = (
            original_evaluator
        )
