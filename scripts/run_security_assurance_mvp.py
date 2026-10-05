#!/usr/bin/env python3

import argparse
import json
import sys

from copy import deepcopy
from pathlib import Path

from jsonschema import (
    ValidationError,
    validate,
)


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from modules.prioritize import (
    prioritize_assessment,
)

from modules.remediation_policy import (
    attach_assessment_policy,
)

from modules.execution_plan import (
    attach_execution_plan,
)

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


MVP_VERSION = "1.0"


def load_json(path):
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            f"Input file does not exist: {path}"
        )

    try:
        return json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in {path}: {exc}"
        ) from exc


def write_json(path, value):
    path = Path(path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            value,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


def validate_assessment(assessment):
    schema = load_json(
        ROOT
        / "schemas"
        / "finding-schema.json"
    )

    try:
        validate(
            instance=assessment,
            schema=schema,
        )

    except ValidationError as exc:
        raise ValueError(
            "Assessment failed schema "
            f"validation: {exc.message}"
        ) from exc


def validate_report(report):
    schema = load_json(
        ROOT
        / "schemas"
        / "security-assurance-report-schema.json"
    )

    try:
        validate(
            instance=report,
            schema=schema,
        )

    except ValidationError as exc:
        raise ValueError(
            "Security Assurance Report "
            "failed schema validation: "
            f"{exc.message}"
        ) from exc


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Run the Cloud Security Labs MVP "
            "assurance pipeline."
        )
    )

    parser.add_argument(
        "--assessment",
        required=True,
        help="Input structured assessment JSON",
    )

    parser.add_argument(
        "--trust-report",
        help=(
            "Optional trust decision report JSON"
        ),
    )

    parser.add_argument(
        "--environment",
        choices=(
            "lab",
            "staging",
            "production",
        ),
        default="lab",
    )

    parser.add_argument(
        "--output-dir",
        default="report/mvp",
    )

    parser.add_argument(
        "--enforce-gate",
        action="store_true",
        help=(
            "Return the security gate exit code "
            "when the gate fails"
        ),
    )

    return parser.parse_args()


def main():
    args = parse_args()

    try:
        assessment = load_json(
            args.assessment
        )

        validate_assessment(
            assessment
        )

        working = deepcopy(
            assessment
        )

        working.setdefault(
            "asset",
            {},
        )["environment"] = (
            args.environment
        )

        prioritized = (
            prioritize_assessment(
                working
            )
        )

        policy_assessment = (
            attach_assessment_policy(
                prioritized,
                environment=(
                    args.environment
                ),
            )
        )

        planned_assessment = (
            attach_execution_plan(
                policy_assessment,
                environment=(
                    args.environment
                ),
            )
        )

        trust_report = None

        if args.trust_report:
            trust_report = load_json(
                args.trust_report
            )

        report = (
            build_security_assurance_report(
                planned_assessment,
                trust_report,
            )
        )

        validate_report(
            report
        )

        loaded_policy = (
            load_security_gate_policy(
                args.environment
            )
        )

        gate_result = (
            evaluate_security_gate(
                report,
                loaded_policy["gate"],
            )
        )

        gate_result[
            "policy_context"
        ] = {
            "policy_version": (
                loaded_policy[
                    "document"
                ].get(
                    "policy_version"
                )
            ),
            "policy_name": (
                loaded_policy[
                    "document"
                ].get(
                    "policy_name"
                )
            ),
            "environment": (
                args.environment
            ),
            "policy_path": (
                loaded_policy["path"]
            ),
        }

        output_dir = Path(
            args.output_dir
        )

        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        prioritized_path = (
            output_dir
            / "01_prioritized_assessment.json"
        )

        policy_path = (
            output_dir
            / "02_policy_assessment.json"
        )

        plan_path = (
            output_dir
            / "03_execution_plan_assessment.json"
        )

        report_json_path = (
            output_dir
            / "security_assurance_report.json"
        )

        report_html_path = (
            output_dir
            / "security_assurance_report.html"
        )

        gate_path = (
            output_dir
            / "security_gate_result.json"
        )

        summary_path = (
            output_dir
            / "mvp_run_summary.json"
        )

        write_json(
            prioritized_path,
            prioritized,
        )

        write_json(
            policy_path,
            policy_assessment,
        )

        write_json(
            plan_path,
            planned_assessment,
        )

        write_security_assurance_report(
            report,
            json_path=(
                report_json_path
            ),
            html_path=(
                report_html_path
            ),
        )

        write_json(
            gate_path,
            gate_result,
        )

        run_summary = {
            "mvp_version": (
                MVP_VERSION
            ),
            "environment": (
                args.environment
            ),
            "assessment_id": (
                planned_assessment
                .get(
                    "assessment",
                    {},
                )
                .get(
                    "assessment_id"
                )
            ),
            "stages": {
                "assessment_validation": (
                    "passed"
                ),
                "prioritization": (
                    "completed"
                ),
                "policy_guardrails": (
                    "completed"
                ),
                "execution_plan": (
                    "completed"
                ),
                "remediation_execution": (
                    "not_executed"
                ),
                "assurance_report": (
                    "completed"
                ),
                "security_gate": (
                    gate_result[
                        "decision"
                    ]
                ),
            },
            "outputs": {
                "prioritized_assessment": (
                    str(
                        prioritized_path
                    )
                ),
                "policy_assessment": (
                    str(
                        policy_path
                    )
                ),
                "execution_plan": (
                    str(
                        plan_path
                    )
                ),
                "assurance_json": (
                    str(
                        report_json_path
                    )
                ),
                "assurance_html": (
                    str(
                        report_html_path
                    )
                ),
                "gate_result": (
                    str(
                        gate_path
                    )
                ),
            },
        }

        write_json(
            summary_path,
            run_summary,
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

    print(
        "Security Assurance MVP completed"
    )

    print(
        "Environment: "
        f"{args.environment}"
    )

    print(
        "Findings: "
        f"{len(planned_assessment.get('findings', []))}"
    )

    print(
        "Security gate: "
        f"{gate_result['decision']}"
    )

    print(
        "Assurance state: "
        f"{report['executive_summary']['assurance_state']}"
    )

    print(
        f"Output: {output_dir}"
    )

    if (
        args.enforce_gate
        and not gate_result["passed"]
    ):
        return gate_result[
            "exit_code"
        ]

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
