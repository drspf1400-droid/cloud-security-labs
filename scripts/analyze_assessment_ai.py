#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from modules.ai_analysis import (
    analyze_assessment,
)

from modules.ai_providers import (
    deterministic_mock_analyzer,
)


def load_json(path):
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            f"Input file does not exist: {path}"
        )

    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


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


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Generate advisory AI-assisted "
            "security finding analysis."
        )
    )

    parser.add_argument(
        "input_assessment",
    )

    parser.add_argument(
        "output_report",
    )

    parser.add_argument(
        "--provider",
        choices=("mock",),
        default="mock",
    )

    parser.add_argument(
        "--model",
        default="deterministic-mock-v1",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    assessment = load_json(
        args.input_assessment
    )

    if args.provider == "mock":
        analyzer = (
            deterministic_mock_analyzer
        )
        provider_name = (
            "deterministic-mock"
        )
    else:
        raise ValueError(
            f"Unsupported provider: "
            f"{args.provider}"
        )

    report = analyze_assessment(
        assessment,
        analyzer,
        provider_name=provider_name,
        model_name=args.model,
    )

    write_json(
        args.output_report,
        report,
    )

    print(
        "AI ANALYSIS REPORT CREATED: "
        f"{args.output_report}"
    )

    print(
        "Mode: advisory-only"
    )

    print(
        "Execution authorized: false"
    )

    print(
        "Findings analyzed: "
        f"{len(report['analyses'])}"
    )


if __name__ == "__main__":
    main()
