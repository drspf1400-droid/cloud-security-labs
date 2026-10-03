import json
import subprocess
import sys

from pathlib import Path

from modules.approver_trust_registry import (
    approver_registry_fingerprint,
)


ROOT = Path(__file__).resolve().parents[1]

SCRIPT = (
    ROOT
    / "scripts"
    / "verify_approver_registry_integrity.py"
)


def run_cli(*args):
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            *map(str, args),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def sample_registry():
    return {
        "registry_version": "1.0",
        "registry_id": "TEST-REGISTRY",
        "created_at": (
            "2026-10-03T10:00:00+00:00"
        ),
        "updated_at": (
            "2026-10-03T10:00:00+00:00"
        ),
        "approvers": [],
    }


def test_matching_registry_fingerprint_passes(
    tmp_path,
):
    registry = sample_registry()

    path = (
        tmp_path
        / "trusted-approvers.json"
    )

    path.write_text(
        json.dumps(
            registry,
            indent=2,
        ),
        encoding="utf-8",
    )

    expected = (
        approver_registry_fingerprint(
            registry
        )
    )

    output = (
        tmp_path
        / "integrity.json"
    )

    result = run_cli(
        "--registry",
        path,
        "--expected-sha256",
        expected,
        "--output",
        output,
    )

    assert result.returncode == 0

    saved = json.loads(
        output.read_text(
            encoding="utf-8"
        )
    )

    assert saved["integrity_ok"] is True


def test_registry_drift_returns_exit_7(
    tmp_path,
):
    registry = sample_registry()

    path = (
        tmp_path
        / "trusted-approvers.json"
    )

    path.write_text(
        json.dumps(registry),
        encoding="utf-8",
    )

    result = run_cli(
        "--registry",
        path,
        "--expected-sha256",
        "0" * 64,
    )

    assert result.returncode == 7

    assert (
        "FAILED"
        in result.stdout
    )


def test_missing_registry_returns_error(
    tmp_path,
):
    result = run_cli(
        "--registry",
        tmp_path / "missing.json",
        "--expected-sha256",
        "0" * 64,
    )

    assert result.returncode == 1
