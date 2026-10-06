#!/usr/bin/env python3

import argparse
import json
import sys

from copy import deepcopy
from functools import partial
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

from modules.ai_analysis import (
    analyze_assessment,
)

from modules.ai_providers import (
    deterministic_mock_analyzer,
    ollama_json_analyzer,
)

from modules.remediation_policy import (
    attach_assessment_policy,
)

from modules.execution_plan import (
    attach_execution_plan,
)

from modules.execution_engine import (
    execute_assessment_plan,
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

DEFAULT_OLLAMA_ENDPOINT = (
    "http://127.0.0.1:11434/api/chat"
)

DEFAULT_OLLAMA_MODEL = "qwen2.5:3b"


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


def build_ai_analyzer(args):
    if args.ai_provider == "mock":
        return (
            deterministic_mock_analyzer,
            "deterministic-mock",
            args.ai_model
            or "deterministic-mock-v1",
        )

    if args.ai_provider == "ollama":
        model = (
            args.ai_model
            or DEFAULT_OLLAMA_MODEL
        )

        analyzer = partial(
            ollama_json_analyzer,
            endpoint=args.ai_endpoint,
            model=model,
            timeout=args.ai_timeout,
        )

        return (
            analyzer,
            "ollama",
            model,
        )

    raise ValueError(
        f"Unsupported AI provider: "
        f"{args.ai_provider}"
    )


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
        "--enable-ai-analysis",
        action="store_true",
        help=(
            "Enable advisory AI-assisted "
            "finding analysis."
        ),
    )

    parser.add_argument(
        "--ai-provider",
        choices=(
            "mock",
            "ollama",
        ),
        default="mock",
    )

    parser.add_argument(
        "--ai-model",
        default=None,
    )

    parser.add_argument(
        "--ai-endpoint",
        default=DEFAULT_OLLAMA_ENDPOINT,
    )

    parser.add_argument(
        "--ai-timeout",
        type=int,
        default=60,
    )

    parser.add_argument(
        "--execute-remediation",
        action="store_true",
        help=(
            "Explicitly enable controlled "
            "remediation execution. Disabled "
            "by default."
        ),
    )

    parser.add_argument(
        "--actor",
        help=(
            "Identity responsible for the "
            "remediation execution"
        ),
    )

    parser.add_argument(
        "--execution-context",
        help=(
            "Optional JSON file mapping finding "
            "IDs to execution context"
        ),
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

        ai_analysis_report = None

        if args.enable_ai_analysis:
            (
                ai_analyzer,
                ai_provider_name,
                ai_model_name,
            ) = build_ai_analyzer(
                args
            )

            ai_analysis_report = (
                analyze_assessment(
                    prioritized,
                    ai_analyzer,
                    provider_name=(
                        ai_provider_name
                    ),
                    model_name=(
                        ai_model_name
                    ),
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

        execution_result = None
        execution_context = {}

        if args.execute_remediation:
            if not args.actor:
                raise ValueError(
                    "--actor is required when "
                    "--execute-remediation is enabled"
                )

            if args.execution_context:
                execution_context = load_json(
                    args.execution_context
                )

                if not isinstance(
                    execution_context,
                    dict,
                ):
                    raise ValueError(
                        "Execution context must be "
                        "a JSON object"
                    )

            execution_result = (
                execute_assessment_plan(
                    planned_assessment,
                    actor=args.actor,
                    environment=(
                        args.environment
                    ),
                    execution_context=(
                        execution_context
                    ),
                )
            )

            effective_assessment = (
                execution_result[
                    "assessment"
                ]
            )

        else:
            effective_assessment = (
                planned_assessment
            )

        trust_report = None

        if args.trust_report:
            trust_report = load_json(
                args.trust_report
            )

        report = (
            build_security_assurance_report(
                effective_assessment,
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

        ai_analysis_path = (
            output_dir
            / "ai_analysis_report.json"
        )

        policy_path = (
            output_dir
            / "02_policy_assessment.json"
        )

        plan_path = (
            output_dir
            / "03_execution_plan_assessment.json"
        )

        execution_path = (
            output_dir
            / "04_execution_assessment.json"
        )

        evidence_path = (
            output_dir
            / "execution_evidence.json"
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

        if ai_analysis_report is not None:
            write_json(
                ai_analysis_path,
                ai_analysis_report,
            )

        write_json(
            policy_path,
            policy_assessment,
        )

        write_json(
            plan_path,
            planned_assessment,
        )

        if execution_result is not None:
            write_json(
                execution_path,
                effective_assessment,
            )

            write_json(
                evidence_path,
                execution_result[
                    "evidence_manifest"
                ],
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
                "ai_analysis": (
                    "completed"
                    if ai_analysis_report
                    is not None
                    else "not_enabled"
                ),
                "policy_guardrails": (
                    "completed"
                ),
                "execution_plan": (
                    "completed"
                ),
                "remediation_execution": (
                    "completed"
                    if execution_result
                    is not None
                    else "not_executed"
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
                "ai_analysis": (
                    str(
                        ai_analysis_path
                    )
                    if ai_analysis_report
                    is not None
                    else None
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
                "execution_assessment": (
                    str(
                        execution_path
                    )
                    if execution_result
                    is not None
                    else None
                ),
                "execution_evidence": (
                    str(
                        evidence_path
                    )
                    if execution_result
                    is not None
                    else None
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

    if execution_result is None:
        print(
            "Remediation execution: DISABLED"
        )
    else:
        print(
            "Remediation execution: COMPLETED"
        )

        print(
            "Execution summary: "
            f"{execution_result['summary']}"
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
