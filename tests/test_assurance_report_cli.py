import json
import subprocess
import sys
from pathlib import Path

from jsonschema import validate


ROOT = Path(__file__).resolve().parents[1]

SCRIPT = (
    ROOT
    / "scripts"
    / "generate_assurance_report.py"
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


def test_cli_generates_json_and_html(tmp_path):
    output_dir = tmp_path / "report"

    result = run_cli(
        "--assessment",
        ROOT / "schemas/finding-example.json",
        "--trust-report",
        ROOT / "report/trust_decision_report.json",
        "--output-dir",
        output_dir,
        "--report-id",
        "CLI-TEST-001",
        "--generated-at",
        "2026-10-03T09:30:00+03:30",
    )

    assert result.returncode == 0
    assert (
        "Security Assurance Report generated"
        in result.stdout
    )

    json_path = (
        output_dir
        / "security_assurance_report.json"
    )

    html_path = (
        output_dir
        / "security_assurance_report.html"
    )

    assert json_path.exists()
    assert html_path.exists()

    report = json.loads(
        json_path.read_text(
            encoding="utf-8"
        )
    )

    assert report["report_id"] == "CLI-TEST-001"

    assert (
        report["executive_summary"][
            "assurance_state"
        ]
        == "attention_required"
    )

    assert (
        report["executive_summary"][
            "trust_decision"
        ]
        == "accept"
    )


def test_cli_output_matches_schema(tmp_path):
    output_dir = tmp_path / "schema-report"

    result = run_cli(
        "--assessment",
        ROOT / "schemas/finding-example.json",
        "--trust-report",
        ROOT / "report/trust_decision_report.json",
        "--output-dir",
        output_dir,
    )

    assert result.returncode == 0

    report = json.loads(
        (
            output_dir
            / "security_assurance_report.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    schema = json.loads(
        (
            ROOT
            / "schemas"
            / "security-assurance-report-schema.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    validate(
        instance=report,
        schema=schema,
    )


def test_cli_rejects_missing_assessment(tmp_path):
    result = run_cli(
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


def test_cli_rejects_invalid_json(tmp_path):
    bad_file = tmp_path / "bad.json"

    bad_file.write_text(
        "{ invalid json",
        encoding="utf-8",
    )

    result = run_cli(
        "--assessment",
        bad_file,
        "--output-dir",
        tmp_path / "output",
    )

    assert result.returncode == 1
    assert "Invalid JSON" in result.stderr


def test_cli_can_run_without_trust_report(
    tmp_path,
):
    output_dir = tmp_path / "no-trust"

    result = run_cli(
        "--assessment",
        ROOT / "schemas/finding-example.json",
        "--output-dir",
        output_dir,
    )

    assert result.returncode == 0

    report = json.loads(
        (
            output_dir
            / "security_assurance_report.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    assert (
        report["executive_summary"][
            "trust_decision"
        ]
        == "unknown"
    )

    assert (
        report["assurance_controls"][
            "trust_decision_present"
        ]
        is False
    )
