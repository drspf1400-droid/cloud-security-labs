import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SCRIPT = (
    ROOT
    / "scripts"
    / "verify_security_policy_integrity.py"
)

SOURCE_POLICY_DIR = (
    ROOT
    / "policies"
    / "security-gates"
)


def run_cli(*args):
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


def test_integrity_cli_accepts_trusted_policies(
    tmp_path,
):
    output = (
        tmp_path
        / "integrity-result.json"
    )

    result = run_cli(
        "--output",
        output,
    )

    assert result.returncode == 0

    assert (
        "Policy integrity: OK"
        in result.stdout
    )

    saved = json.loads(
        output.read_text(
            encoding="utf-8"
        )
    )

    assert saved["integrity_ok"] is True


def test_integrity_cli_detects_policy_drift(
    tmp_path,
):
    policy_dir = (
        tmp_path
        / "policies"
    )

    policy_dir.mkdir()

    for name in (
        "lab.json",
        "staging.json",
        "production.json",
    ):
        shutil.copy(
            SOURCE_POLICY_DIR / name,
            policy_dir / name,
        )

    manifest = (
        tmp_path
        / "trusted-manifest.json"
    )

    shutil.copy(
        SOURCE_POLICY_DIR
        / "trusted-manifest.json",
        manifest,
    )

    production_path = (
        policy_dir
        / "production.json"
    )

    production = json.loads(
        production_path.read_text(
            encoding="utf-8"
        )
    )

    production["gate"][
        "max_blocked_executions"
    ] = 5

    production_path.write_text(
        json.dumps(
            production,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    output = (
        tmp_path
        / "drift-result.json"
    )

    result = run_cli(
        "--policy-dir",
        policy_dir,
        "--manifest",
        manifest,
        "--output",
        output,
    )

    assert result.returncode == 3

    assert (
        "DRIFT DETECTED"
        in result.stdout
    )

    saved = json.loads(
        output.read_text(
            encoding="utf-8"
        )
    )

    assert saved["integrity_ok"] is False
    assert saved["summary"]["drifted"] == 1


def test_integrity_cli_rejects_missing_manifest(
    tmp_path,
):
    result = run_cli(
        "--manifest",
        tmp_path / "missing.json",
    )

    assert result.returncode == 1

    assert (
        "File does not exist"
        in result.stderr
    )
