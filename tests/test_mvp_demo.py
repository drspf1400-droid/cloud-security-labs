import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SCRIPT = (
    ROOT
    / "scripts"
    / "demo_security_assurance_mvp.sh"
)


def test_security_assurance_mvp_demo(tmp_path):
    workdir = tmp_path / "mvp-demo"

    result = subprocess.run(
        [
            str(SCRIPT),
            str(workdir),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, (
        result.stderr
    )

    assert (
        "Demo completed successfully."
        in result.stdout
    )

    assert (
        "Finding status: remediated"
        in result.stdout
    )

    assert (
        "Remediation applied: True"
        in result.stdout
    )

    assert (
        "Verification passed: True"
        in result.stdout
    )

    assert (
        "Security gate: pass"
        in result.stdout
    )

    target = (
        workdir
        / "sshd_config"
    )

    assert target.exists()

    assert (
        "PermitRootLogin no"
        in target.read_text(
            encoding="utf-8"
        )
    )

    output = (
        workdir
        / "output"
    )

    expected_artifacts = [
        "01_prioritized_assessment.json",
        "02_policy_assessment.json",
        "03_execution_plan_assessment.json",
        "04_execution_assessment.json",
        "execution_evidence.json",
        "security_assurance_report.json",
        "security_assurance_report.html",
        "security_gate_result.json",
        "mvp_run_summary.json",
    ]

    for name in expected_artifacts:
        assert (
            output / name
        ).exists()
