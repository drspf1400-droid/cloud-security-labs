import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SCRIPT = (
    ROOT
    / "scripts"
    / "run_security_assurance_mvp.py"
)


def run_mvp(*args):
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            *map(str, args),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def test_lab_mvp_pipeline_generates_outputs(
    tmp_path,
):
    output_dir = (
        tmp_path / "mvp-lab"
    )

    result = run_mvp(
        "--assessment",
        ROOT
        / "schemas"
        / "finding-example.json",
        "--trust-report",
        ROOT
        / "report"
        / "trust_decision_report.json",
        "--environment",
        "lab",
        "--output-dir",
        output_dir,
        "--enforce-gate",
    )

    assert result.returncode == 0, (
        result.stderr
    )

    expected = [
        "01_prioritized_assessment.json",
        "02_policy_assessment.json",
        "03_execution_plan_assessment.json",
        "security_assurance_report.json",
        "security_assurance_report.html",
        "security_gate_result.json",
        "mvp_run_summary.json",
    ]

    for name in expected:
        assert (
            output_dir / name
        ).exists()

    prioritized = json.loads(
        (
            output_dir
            / "01_prioritized_assessment.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    assert all(
        "priority" in finding
        for finding in prioritized[
            "findings"
        ]
    )

    summary = json.loads(
        (
            output_dir
            / "mvp_run_summary.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    assert (
        summary["stages"][
            "remediation_execution"
        ]
        == "not_executed"
    )

    assert (
        summary["stages"][
            "security_gate"
        ]
        == "pass"
    )


def test_production_mvp_gate_fails_closed(
    tmp_path,
):
    result = run_mvp(
        "--assessment",
        ROOT
        / "schemas"
        / "finding-example.json",
        "--trust-report",
        ROOT
        / "report"
        / "trust_decision_report.json",
        "--environment",
        "production",
        "--output-dir",
        tmp_path / "mvp-prod",
        "--enforce-gate",
    )

    assert result.returncode == 2

    assert (
        "Security gate: fail"
        in result.stdout
    )


def test_mvp_without_enforcement_still_records_gate(
    tmp_path,
):
    output_dir = (
        tmp_path / "mvp-no-enforce"
    )

    result = run_mvp(
        "--assessment",
        ROOT
        / "schemas"
        / "finding-example.json",
        "--environment",
        "production",
        "--output-dir",
        output_dir,
    )

    assert result.returncode == 0

    gate = json.loads(
        (
            output_dir
            / "security_gate_result.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    assert gate["passed"] is False


def test_mvp_rejects_missing_assessment(
    tmp_path,
):
    result = run_mvp(
        "--assessment",
        tmp_path / "missing.json",
        "--output-dir",
        tmp_path / "output",
    )

    assert result.returncode == 1

    assert (
        "Input file does not exist"
        in result.stderr
    )


def build_approved_ssh_assessment(
    tmp_path,
):
    assessment = {
        "schema_version": "1.0",
        "assessment": {
            "assessment_id": "MVP-SSH-001",
            "scanner": {
                "name": "test-scanner",
                "version": "1.0"
            },
            "score": 60,
            "risk_level": "high"
        },
        "asset": {
            "asset_id": "LAB-SSH-001",
            "hostname": "lab-ssh",
            "asset_type": "linux_server",
            "environment": "lab",
            "internet_exposed": False,
            "business_criticality": "medium"
        },
        "findings": [
            {
                "finding_id": "SSH-002",
                "category": "ssh",
                "title": "SSH root login permitted",
                "baseline_severity": "high",
                "status": "approved",
                "source": {
                    "type": "linux_configuration",
                    "module": "ssh_check"
                },
                "evidence": {
                    "type": "configuration",
                    "source": "/etc/ssh/sshd_config",
                    "key": "PermitRootLogin",
                    "observed_value": "yes"
                },
                "classification": {
                    "cve": None,
                    "cwe": None,
                    "cvss": None
                },
                "remediation": {
                    "recommendation": (
                        "Disable direct SSH root login."
                    ),
                    "approval_status": "approved",
                    "applied": False
                },
                "verification": {
                    "security": "not_tested",
                    "configuration": "not_tested",
                    "functionality": "not_tested"
                }
            }
        ]
    }

    path = (
        tmp_path
        / "approved-ssh-assessment.json"
    )

    path.write_text(
        json.dumps(
            assessment,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )

    return path


def test_mvp_default_mode_never_executes_remediation(
    tmp_path,
):
    assessment_path = (
        build_approved_ssh_assessment(
            tmp_path
        )
    )

    source = (
        ROOT
        / "tests"
        / "fixtures"
        / "sshd_config.insecure"
    )

    target = tmp_path / "sshd_config"
    target.write_text(
        source.read_text()
    )

    original = target.read_text()

    context_path = (
        tmp_path
        / "execution-context.json"
    )

    context_path.write_text(
        json.dumps(
            {
                "SSH-002": {
                    "config_path": str(
                        target
                    )
                }
            }
        ),
        encoding="utf-8",
    )

    output_dir = (
        tmp_path / "default-safe"
    )

    result = run_mvp(
        "--assessment",
        assessment_path,
        "--environment",
        "lab",
        "--execution-context",
        context_path,
        "--output-dir",
        output_dir,
    )

    assert result.returncode == 0
    assert target.read_text() == original

    summary = json.loads(
        (
            output_dir
            / "mvp_run_summary.json"
        ).read_text()
    )

    assert (
        summary["stages"][
            "remediation_execution"
        ]
        == "not_executed"
    )

    assert not (
        output_dir
        / "04_execution_assessment.json"
    ).exists()


def test_mvp_explicit_lab_execution_applies_approved_remediation(
    tmp_path,
):
    assessment_path = (
        build_approved_ssh_assessment(
            tmp_path
        )
    )

    source = (
        ROOT
        / "tests"
        / "fixtures"
        / "sshd_config.insecure"
    )

    target = tmp_path / "sshd_config"
    target.write_text(
        source.read_text()
    )

    context_path = (
        tmp_path
        / "execution-context.json"
    )

    context_path.write_text(
        json.dumps(
            {
                "SSH-002": {
                    "config_path": str(
                        target
                    )
                }
            }
        ),
        encoding="utf-8",
    )

    output_dir = (
        tmp_path / "explicit-lab"
    )

    result = run_mvp(
        "--assessment",
        assessment_path,
        "--environment",
        "lab",
        "--execute-remediation",
        "--actor",
        "security-reviewer",
        "--execution-context",
        context_path,
        "--output-dir",
        output_dir,
    )

    assert result.returncode == 0, (
        result.stderr
    )

    assert (
        "PermitRootLogin no"
        in target.read_text()
    )

    executed = json.loads(
        (
            output_dir
            / "04_execution_assessment.json"
        ).read_text()
    )

    assert (
        executed["assessment"][
            "execution"
        ]["summary"]["executed"]
        == 1
    )

    assert (
        output_dir
        / "execution_evidence.json"
    ).exists()


def test_mvp_execution_requires_actor(
    tmp_path,
):
    assessment_path = (
        build_approved_ssh_assessment(
            tmp_path
        )
    )

    result = run_mvp(
        "--assessment",
        assessment_path,
        "--environment",
        "lab",
        "--execute-remediation",
        "--output-dir",
        tmp_path / "missing-actor",
    )

    assert result.returncode == 1

    assert (
        "--actor is required"
        in result.stderr
    )


def test_mvp_production_execution_remains_dry_run(
    tmp_path,
):
    assessment_path = (
        build_approved_ssh_assessment(
            tmp_path
        )
    )

    source = (
        ROOT
        / "tests"
        / "fixtures"
        / "sshd_config.insecure"
    )

    target = tmp_path / "sshd_config"
    target.write_text(
        source.read_text()
    )

    original = target.read_text()

    context_path = (
        tmp_path
        / "production-context.json"
    )

    context_path.write_text(
        json.dumps(
            {
                "SSH-002": {
                    "config_path": str(
                        target
                    )
                }
            }
        ),
        encoding="utf-8",
    )

    output_dir = (
        tmp_path / "production-dry-run"
    )

    result = run_mvp(
        "--assessment",
        assessment_path,
        "--environment",
        "production",
        "--execute-remediation",
        "--actor",
        "security-reviewer",
        "--execution-context",
        context_path,
        "--output-dir",
        output_dir,
    )

    assert result.returncode == 0, (
        result.stderr
    )

    assert target.read_text() == original

    executed = json.loads(
        (
            output_dir
            / "04_execution_assessment.json"
        ).read_text()
    )

    summary = (
        executed["assessment"][
            "execution"
        ]["summary"]
    )

    assert summary["executed"] == 0
    assert summary["dry_run"] == 1
