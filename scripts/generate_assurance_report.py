#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path

from jsonschema import ValidationError, validate

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.security_assurance_report import (
    build_security_assurance_report,
    write_security_assurance_report,
)

from modules.security_gate import (
    evaluate_security_gate,
)

from modules.security_gate_policy import (
    SecurityGatePolicyError,
    load_security_gate_policy,
)


def load_json(path):
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            f"Input file does not exist: {path}"
        )

    try:
        return json.loads(
            path.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in {path}: {exc}"
        ) from exc


def validate_report(report):
    schema_path = (
        ROOT
        / "schemas"
        / "security-assurance-report-schema.json"
    )

    schema = load_json(schema_path)

    try:
        validate(
            instance=report,
            schema=schema,
        )
    except ValidationError as exc:
        raise ValueError(
            "Generated report failed schema validation: "
            f"{exc.message}"
        ) from exc


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Generate a professional Security "
            "Assurance Report."
        )
    )

    parser.add_argument(
        "--assessment",
        required=True,
        help="Path to assessment JSON",
    )

    parser.add_argument(
        "--trust-report",
        help="Path to trust decision report JSON",
    )

    parser.add_argument(
        "--output-dir",
        default="report/generated",
        help=(
            "Directory for generated report files "
            "(default: report/generated)"
        ),
    )

    parser.add_argument(
        "--report-id",
        help="Optional explicit report identifier",
    )

    parser.add_argument(
        "--generated-at",
        help=(
            "Optional explicit ISO-8601 generation "
            "timestamp"
        ),
    )

    parser.add_argument(
        "--enforce-gate",
        action="store_true",
        help=(
            "Evaluate the CI/CD security gate and "
            "exit with code 2 when the gate fails"
        ),
    )

    parser.add_argument(
        "--environment",
        choices=[
            "lab",
            "staging",
            "production",
        ],
        default="production",
        help=(
            "Security gate policy environment "
            "(default: production)"
        ),
    )

    return parser.parse_args()


def main():
    args = parse_args()

    try:
        assessment = load_json(
            args.assessment
        )

        trust_report = None

        if args.trust_report:
            trust_report = load_json(
                args.trust_report
            )

        report = build_security_assurance_report(
            assessment,
            trust_report,
            report_id=args.report_id,
            generated_at=args.generated_at,
        )

        validate_report(report)

        output_dir = Path(
            args.output_dir
        )

        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        json_path = (
            output_dir
            / "security_assurance_report.json"
        )

        html_path = (
            output_dir
            / "security_assurance_report.html"
        )

        write_security_assurance_report(
            report,
            json_path=json_path,
            html_path=html_path,
        )

        gate_result = None

        if args.enforce_gate:
            loaded_policy = (
                load_security_gate_policy(
                    args.environment
                )
            )

            gate_result = evaluate_security_gate(
                report,
                loaded_policy["gate"],
            )

            gate_result[
                "policy_context"
            ] = {
                "policy_version": (
                    loaded_policy["document"]
                    .get("policy_version")
                ),
                "policy_name": (
                    loaded_policy["document"]
                    .get("policy_name")
                ),
                "environment": (
                    loaded_policy["document"]
                    .get("environment")
                ),
                "policy_path": (
                    loaded_policy["path"]
                ),
            }

            gate_path = (
                output_dir
                / "security_gate_result.json"
            )

            gate_path.write_text(
                json.dumps(
                    gate_result,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

    except (
        FileNotFoundError,
        ValueError,
        SecurityGatePolicyError,
        OSError,
    ) as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )
        return 1

    summary = report[
        "executive_summary"
    ]

    print("Security Assurance Report generated")
    print(f"JSON: {json_path}")
    print(f"HTML: {html_path}")
    print(
        "Assurance state: "
        f"{summary.get('assurance_state')}"
    )
    print(
        "Trust decision: "
        f"{summary.get('trust_decision')}"
    )
    print(
        "Security score: "
        f"{summary.get('security_score')}"
    )

    if args.enforce_gate:
        print(
            "Security gate: "
            f"{gate_result.get('decision')}"
        )

        print(
            "Gate environment: "
            f"{args.environment}"
        )

        print(
            "Gate policy: "
            f"{gate_result['policy_context'].get('policy_name')}"
        )

        print(
            "Gate result: "
            f"{gate_path}"
        )

        if not gate_result.get("passed"):
            for reason in gate_result.get(
                "reasons",
                [],
            ):
                print(
                    "Gate failure: "
                    f"{reason.get('code')} - "
                    f"{reason.get('message')}"
                )

            return gate_result["exit_code"]

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
