import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SCRIPT = (
    ROOT
    / "scripts"
    / "analyze_assessment_ai.py"
)

INPUT = (
    ROOT
    / "schemas"
    / "finding-example.json"
)


def run_cli(output_path):
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            str(INPUT),
            str(output_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def test_ai_analysis_cli_creates_advisory_report(
    tmp_path,
):
    output = (
        tmp_path
        / "ai-analysis-report.json"
    )

    result = run_cli(output)

    assert result.returncode == 0, (
        result.stderr
    )

    assert output.exists()

    report = json.loads(
        output.read_text(
            encoding="utf-8"
        )
    )

    assert (
        report["advisory_only"]
        is True
    )

    assert report["analyses"]

    for analysis in report["analyses"]:
        assert (
            analysis[
                "requires_human_review"
            ]
            is True
        )

        assert (
            analysis[
                "execution_authorized"
            ]
            is False
        )

    assert (
        "Mode: advisory-only"
        in result.stdout
    )

    assert (
        "Execution authorized: false"
        in result.stdout
    )


def test_mock_ai_analysis_is_deterministic(
    tmp_path,
):
    first = (
        tmp_path
        / "first.json"
    )

    second = (
        tmp_path
        / "second.json"
    )

    first_result = run_cli(first)
    second_result = run_cli(second)

    assert first_result.returncode == 0
    assert second_result.returncode == 0

    assert (
        first.read_text(
            encoding="utf-8"
        )
        ==
        second.read_text(
            encoding="utf-8"
        )
    )
