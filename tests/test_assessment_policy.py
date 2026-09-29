import importlib.util
from copy import deepcopy
from pathlib import Path


MODULE_PATH = Path("modules/remediation_policy.py")

spec = importlib.util.spec_from_file_location(
    "remediation_policy",
    MODULE_PATH,
)

policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


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


def test_lab_assessment_summary():
    assessment = {
        "findings": [
            approved_ssh_finding(),
            unknown_finding(),
        ]
    }

    result = policy.evaluate_assessment_policy(
        assessment,
        environment="lab",
    )

    assert result["environment"] == "lab"

    assert result["policy_summary"] == {
        "apply": 1,
        "dry_run": 0,
        "blocked": 1,
    }

    assert len(result["decisions"]) == 2

    assert result["decisions"][0]["finding_id"] == "SSH-002"
    assert result["decisions"][0]["decision"] == "apply"

    assert result["decisions"][1]["finding_id"] == "UNKNOWN-001"
    assert result["decisions"][1]["decision"] == "blocked"


def test_production_assessment_summary():
    assessment = {
        "findings": [
            approved_ssh_finding(),
            unknown_finding(),
        ]
    }

    result = policy.evaluate_assessment_policy(
        assessment,
        environment="production",
    )

    assert result["policy_summary"] == {
        "apply": 0,
        "dry_run": 1,
        "blocked": 1,
    }


def test_unapproved_finding_is_counted_as_blocked():
    finding = approved_ssh_finding()
    finding["status"] = "under_review"
    finding["remediation"]["approval_status"] = "pending"

    assessment = {
        "findings": [finding]
    }

    result = policy.evaluate_assessment_policy(
        assessment,
        environment="lab",
    )

    assert result["policy_summary"] == {
        "apply": 0,
        "dry_run": 0,
        "blocked": 1,
    }

    assert result["decisions"][0]["decision"] == "blocked"


def test_empty_assessment_returns_zero_summary():
    result = policy.evaluate_assessment_policy(
        {"findings": []},
        environment="lab",
    )

    assert result["policy_summary"] == {
        "apply": 0,
        "dry_run": 0,
        "blocked": 0,
    }

    assert result["decisions"] == []


def test_input_assessment_is_not_mutated():
    assessment = {
        "findings": [
            approved_ssh_finding(),
        ]
    }

    original = deepcopy(assessment)

    policy.evaluate_assessment_policy(
        assessment,
        environment="lab",
    )

    assert assessment == original


def test_policy_summary_can_be_attached_to_assessment():
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

    result = policy.attach_assessment_policy(
        assessment
    )

    assert assessment == original

    attached = result["assessment"]["remediation_policy"]

    assert attached["environment"] == "lab"

    assert attached["summary"] == {
        "apply": 1,
        "dry_run": 0,
        "blocked": 1,
    }


def test_explicit_environment_overrides_asset_environment():
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

    result = policy.attach_assessment_policy(
        assessment,
        environment="production",
    )

    attached = result["assessment"]["remediation_policy"]

    assert attached["environment"] == "production"

    assert attached["summary"] == {
        "apply": 0,
        "dry_run": 1,
        "blocked": 0,
    }
