import importlib.util
from copy import deepcopy
from pathlib import Path

import pytest


MODULE_PATH = Path("modules/remediation.py")
spec = importlib.util.spec_from_file_location(
    "remediation",
    MODULE_PATH,
)
remediation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remediation)


def sample_finding(
    status="approved",
    approval_status="approved",
):
    return {
        "finding_id": "SSH-002",
        "status": status,
        "remediation": {
            "recommendation": "Disable direct SSH root login.",
            "approval_status": approval_status,
            "applied": False,
        },
    }


def test_approved_finding_allows_dry_run():
    finding = sample_finding()

    remediation.dry_run_finding(
        finding,
        actor="tester",
        note="preview remediation",
        timestamp="2026-01-01T00:10:00Z",
    )

    assert finding["remediation"]["applied"] is False
    assert finding["remediation"]["last_mode"] == "dry-run"

    plan = finding["remediation"]["plan"]

    assert plan["finding_id"] == "SSH-002"
    assert plan["action"] == "disable_ssh_root_login"
    assert plan["mode"] == "dry-run"

    entry = finding["audit_trail"][-1]

    assert entry["action"] == "remediation_dry_run"
    assert entry["actor"] == "tester"
    assert entry["mode"] == "dry-run"
    assert entry["applied"] is False
    assert entry["from_status"] == "approved"
    assert entry["to_status"] == "approved"


def test_non_approved_finding_is_blocked():
    finding = sample_finding(
        status="under_review",
        approval_status="pending",
    )

    with pytest.raises(
        ValueError,
        match="status must be approved",
    ):
        remediation.dry_run_finding(
            finding,
            actor="tester",
        )


def test_missing_human_approval_is_blocked():
    finding = sample_finding(
        status="approved",
        approval_status="pending",
    )

    with pytest.raises(
        ValueError,
        match="human approval is required",
    ):
        remediation.dry_run_finding(
            finding,
            actor="tester",
        )


def test_assessment_dry_run_does_not_mutate_input():
    assessment = {
        "findings": [
            sample_finding()
        ]
    }

    original = deepcopy(assessment)

    result = remediation.dry_run_assessment(
        assessment,
        finding_id="SSH-002",
        actor="tester",
        note="safe preview",
    )

    assert assessment == original

    finding = result["findings"][0]

    assert finding["remediation"]["applied"] is False
    assert finding["remediation"]["plan"]["mode"] == "dry-run"
    assert finding["audit_trail"][-1]["action"] == "remediation_dry_run"


def test_insecure_fixture_fails_verification():
    config_path = Path(
        "tests/fixtures/sshd_config.insecure"
    )

    assert (
        remediation.verify_ssh_root_login_disabled(
            config_path
        )
        is False
    )


def test_apply_remediation_updates_and_verifies_fixture(
    tmp_path,
):
    source = Path(
        "tests/fixtures/sshd_config.insecure"
    )

    target = tmp_path / "sshd_config"
    target.write_text(source.read_text())

    finding = sample_finding()

    remediation.apply_ssh_root_login_remediation(
        finding,
        config_path=target,
        actor="tester",
        note="approved lab remediation",
        timestamp="2026-01-01T00:20:00Z",
    )

    content = target.read_text()

    assert "PermitRootLogin no" in content
    assert "PasswordAuthentication yes" in content

    assert finding["status"] == "remediated"

    remed = finding["remediation"]

    assert remed["applied"] is True
    assert remed["verified"] is True
    assert remed["last_mode"] == "apply"

    actions = [
        entry["action"]
        for entry in finding["audit_trail"]
    ]

    assert actions[-2:] == [
        "remediation_applied",
        "verification_passed",
    ]


def test_apply_without_approval_is_blocked_and_file_unchanged(
    tmp_path,
):
    source = Path(
        "tests/fixtures/sshd_config.insecure"
    )

    target = tmp_path / "sshd_config"
    target.write_text(source.read_text())

    original = target.read_text()

    finding = sample_finding(
        status="under_review",
        approval_status="pending",
    )

    with pytest.raises(
        ValueError,
        match="status must be approved",
    ):
        remediation.apply_ssh_root_login_remediation(
            finding,
            config_path=target,
            actor="tester",
        )

    assert target.read_text() == original


def test_safe_apply_success_does_not_rollback(tmp_path):
    source = Path(
        "tests/fixtures/sshd_config.insecure"
    )

    target = tmp_path / "sshd_config"
    target.write_text(source.read_text())

    finding = sample_finding()

    remediation.safe_apply_ssh_root_login_remediation(
        finding,
        config_path=target,
        actor="tester",
        timestamp="2026-01-01T00:30:00Z",
    )

    assert "PermitRootLogin no" in target.read_text()
    assert finding["status"] == "remediated"

    remed = finding["remediation"]

    assert remed["applied"] is True
    assert remed["verified"] is True
    assert remed["rollback_performed"] is False

    actions = [
        entry["action"]
        for entry in finding["audit_trail"]
    ]

    assert actions[-2:] == [
        "remediation_applied",
        "verification_passed",
    ]


def test_verification_failure_triggers_verified_rollback(
    tmp_path,
    monkeypatch,
):
    source = Path(
        "tests/fixtures/sshd_config.insecure"
    )

    target = tmp_path / "sshd_config"
    target.write_text(source.read_text())

    original = target.read_text()
    finding = sample_finding()

    monkeypatch.setattr(
        remediation,
        "verify_ssh_root_login_disabled",
        lambda config_path: False,
    )

    with pytest.raises(
        RuntimeError,
        match="rollback completed",
    ):
        remediation.safe_apply_ssh_root_login_remediation(
            finding,
            config_path=target,
            actor="tester",
            note="simulate failed verification",
            timestamp="2026-01-01T00:31:00Z",
        )

    # Exact pre-remediation state must be restored.
    assert target.read_text() == original

    # Finding stays approved because it is still unresolved.
    assert finding["status"] == "approved"

    remed = finding["remediation"]

    assert remed["applied"] is False
    assert remed["verified"] is False
    assert remed["rollback_performed"] is True
    assert remed["rollback_verified"] is True

    actions = [
        entry["action"]
        for entry in finding["audit_trail"]
    ]

    assert actions[-4:] == [
        "remediation_applied",
        "verification_failed",
        "rollback_started",
        "rollback_completed",
    ]


def test_direct_apply_is_blocked_in_production(tmp_path):
    source = Path(
        "tests/fixtures/sshd_config.insecure"
    )

    target = tmp_path / "sshd_config"
    target.write_text(source.read_text())

    original = target.read_text()
    finding = sample_finding()

    with pytest.raises(
        ValueError,
        match="blocked by policy",
    ):
        remediation.apply_ssh_root_login_remediation(
            finding,
            config_path=target,
            actor="tester",
            environment="production",
        )

    assert target.read_text() == original
    assert finding["remediation"]["applied"] is False


def test_safe_apply_is_blocked_in_production(tmp_path):
    source = Path(
        "tests/fixtures/sshd_config.insecure"
    )

    target = tmp_path / "sshd_config"
    target.write_text(source.read_text())

    original = target.read_text()
    finding = sample_finding()

    with pytest.raises(
        ValueError,
        match="blocked by policy",
    ):
        remediation.safe_apply_ssh_root_login_remediation(
            finding,
            config_path=target,
            actor="tester",
            environment="production",
        )

    assert target.read_text() == original
    assert finding["remediation"]["applied"] is False
