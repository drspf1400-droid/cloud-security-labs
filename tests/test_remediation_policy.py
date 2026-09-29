import importlib.util
from pathlib import Path


MODULE_PATH = Path("modules/remediation_policy.py")

spec = importlib.util.spec_from_file_location(
    "remediation_policy",
    MODULE_PATH,
)

policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def sample_finding(
    status="approved",
    approval_status="approved",
):
    return {
        "finding_id": "SSH-002",
        "status": status,
        "remediation": {
            "approval_status": approval_status,
            "applied": False,
        },
    }


def test_approved_lab_finding_can_apply():
    result = policy.evaluate_remediation_policy(
        sample_finding(),
        environment="lab",
    )
    assert result["decision"] == "apply"


def test_production_is_dry_run_only():
    result = policy.evaluate_remediation_policy(
        sample_finding(),
        environment="production",
    )
    assert result["decision"] == "dry-run"


def test_unapproved_finding_is_blocked():
    result = policy.evaluate_remediation_policy(
        sample_finding(
            status="under_review",
            approval_status="pending",
        ),
        environment="lab",
    )
    assert result["decision"] == "blocked"


def test_missing_remediation_approval_is_blocked():
    result = policy.evaluate_remediation_policy(
        sample_finding(
            status="approved",
            approval_status="pending",
        ),
        environment="lab",
    )
    assert result["decision"] == "blocked"


def test_unknown_finding_is_blocked():
    finding = sample_finding()
    finding["finding_id"] = "UNKNOWN-001"

    result = policy.evaluate_remediation_policy(
        finding,
        environment="lab",
    )
    assert result["decision"] == "blocked"


def test_unknown_environment_is_blocked():
    result = policy.evaluate_remediation_policy(
        sample_finding(),
        environment="unknown",
    )
    assert result["decision"] == "blocked"


def test_staging_is_dry_run_only():
    result = policy.evaluate_remediation_policy(
        sample_finding(),
        environment="staging",
    )

    assert result["decision"] == "dry-run"
