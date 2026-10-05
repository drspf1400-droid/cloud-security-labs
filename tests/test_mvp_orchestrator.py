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
