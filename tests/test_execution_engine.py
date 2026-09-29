import importlib.util
from copy import deepcopy
from pathlib import Path


MODULE_PATH = Path("modules/execution_engine.py")

spec = importlib.util.spec_from_file_location(
    "execution_engine",
    MODULE_PATH,
)

engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


def approved_ssh_finding():
    return {
        "finding_id": "SSH-002",
        "status": "approved",
        "remediation": {
            "recommendation": "Disable direct SSH root login.",
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


def make_assessment(
    finding,
    environment="lab",
):
    return {
        "asset": {
            "environment": environment,
        },
        "findings": [
            finding,
        ],
    }


def test_lab_apply_executes_supported_action(tmp_path):
    source = Path(
        "tests/fixtures/sshd_config.insecure"
    )

    target = tmp_path / "sshd_config"
    target.write_text(source.read_text())

    assessment = make_assessment(
        approved_ssh_finding(),
        environment="lab",
    )

    result = engine.execute_assessment_plan(
        assessment,
        actor="tester",
        execution_context={
            "SSH-002": {
                "config_path": target,
            }
        },
    )

    assert result["summary"] == {
        "executed": 1,
        "dry_run": 0,
        "blocked": 0,
        "failed": 0,
    }

    assert (
        result["results"][0]["status"]
        == "executed"
    )

    assert "PermitRootLogin no" in target.read_text()


def test_production_dry_run_does_not_modify_target(
    tmp_path,
):
    source = Path(
        "tests/fixtures/sshd_config.insecure"
    )

    target = tmp_path / "sshd_config"
    target.write_text(source.read_text())

    original = target.read_text()

    assessment = make_assessment(
        approved_ssh_finding(),
        environment="production",
    )

    result = engine.execute_assessment_plan(
        assessment,
        actor="tester",
        execution_context={
            "SSH-002": {
                "config_path": target,
            }
        },
    )

    assert result["summary"]["dry_run"] == 1
    assert result["summary"]["executed"] == 0
    assert target.read_text() == original


def test_blocked_finding_is_never_executed():
    assessment = make_assessment(
        unknown_finding(),
        environment="lab",
    )

    result = engine.execute_assessment_plan(
        assessment,
        actor="tester",
    )

    assert result["summary"]["blocked"] == 1
    assert result["summary"]["executed"] == 0

    assert (
        result["results"][0]["status"]
        == "blocked"
    )


def test_missing_execution_context_fails_closed():
    assessment = make_assessment(
        approved_ssh_finding(),
        environment="lab",
    )

    result = engine.execute_assessment_plan(
        assessment,
        actor="tester",
    )

    assert result["summary"]["blocked"] == 1
    assert result["summary"]["executed"] == 0

    assert (
        "config_path"
        in result["results"][0]["reason"]
    )


def test_original_assessment_is_not_mutated(tmp_path):
    source = Path(
        "tests/fixtures/sshd_config.insecure"
    )

    target = tmp_path / "sshd_config"
    target.write_text(source.read_text())

    assessment = make_assessment(
        approved_ssh_finding(),
        environment="lab",
    )

    original = deepcopy(assessment)

    engine.execute_assessment_plan(
        assessment,
        actor="tester",
        execution_context={
            "SSH-002": {
                "config_path": target,
            }
        },
    )

    assert assessment == original


def test_empty_assessment_executes_nothing():
    assessment = {
        "asset": {
            "environment": "lab",
        },
        "findings": [],
    }

    result = engine.execute_assessment_plan(
        assessment,
        actor="tester",
    )

    assert result["summary"] == {
        "executed": 0,
        "dry_run": 0,
        "blocked": 0,
        "failed": 0,
    }

    assert result["results"] == []


def test_execution_result_contains_audit_trail():
    assessment = make_assessment(
        unknown_finding(),
        environment="lab",
    )

    result = engine.execute_assessment_plan(
        assessment,
        actor="tester",
    )

    assert len(result["audit_trail"]) == 1

    audit = result["audit_trail"][0]

    assert audit["actor"] == "tester"
    assert audit["finding_id"] == "UNKNOWN-001"
    assert audit["status"] == "blocked"

    attached = (
        result["assessment"]
        ["assessment"]
        ["execution"]
    )

    assert attached["summary"]["blocked"] == 1
    assert len(attached["audit_trail"]) == 1


def test_engine_preserves_verified_rollback_on_failure(
    tmp_path,
):
    import modules.remediation as remediation_module

    source = Path(
        "tests/fixtures/sshd_config.insecure"
    )

    target = tmp_path / "sshd_config"
    original_content = source.read_text()
    target.write_text(original_content)

    assessment = make_assessment(
        approved_ssh_finding(),
        environment="lab",
    )

    original_verifier = (
        remediation_module
        .verify_ssh_root_login_disabled
    )

    try:
        remediation_module.verify_ssh_root_login_disabled = (
            lambda config_path: False
        )

        result = engine.execute_assessment_plan(
            assessment,
            actor="tester",
            execution_context={
                "SSH-002": {
                    "config_path": target,
                }
            },
        )

    finally:
        remediation_module.verify_ssh_root_login_disabled = (
            original_verifier
        )

    assert result["summary"] == {
        "executed": 0,
        "dry_run": 0,
        "blocked": 0,
        "failed": 1,
    }

    assert result["results"][0]["status"] == "failed"

    # Exact original file must be restored.
    assert target.read_text() == original_content

    executed_finding = (
        result["assessment"]["findings"][0]
    )

    assert (
        executed_finding["remediation"]
        ["rollback_performed"]
        is True
    )

    actions = [
        entry.get("action")
        for entry in executed_finding.get(
            "audit_trail",
            [],
        )
    ]

    assert "verification_failed" in actions
    assert "rollback_started" in actions
    assert "rollback_completed" in actions

    assert result["audit_trail"][0]["status"] == "failed"
