#!/usr/bin/env python3

import argparse
import json
import sys
from functools import partial
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from modules.ai_analysis import (
    analyze_assessment,
)

from modules.ai_providers import (
    deterministic_mock_analyzer,
    ollama_json_analyzer,
)


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
        choices=(
            "mock",
            "ollama",
        ),
        default="mock",
    )

    parser.add_argument(
        "--model",
        default=None,
    )

    parser.add_argument(
        "--endpoint",
        default=DEFAULT_OLLAMA_ENDPOINT,
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
    )

    return parser.parse_args()


def build_analyzer(args):
    if args.provider == "mock":
        return (
            deterministic_mock_analyzer,
            "deterministic-mock",
            args.model
            or "deterministic-mock-v1",
        )

    if args.provider == "ollama":
        model = (
            args.model
            or DEFAULT_OLLAMA_MODEL
        )

        analyzer = partial(
            ollama_json_analyzer,
            endpoint=args.endpoint,
            model=model,
            timeout=args.timeout,
        )

        return (
            analyzer,
            "ollama",
            model,
        )

    raise ValueError(
        f"Unsupported provider: "
        f"{args.provider}"
    )


def main():
    args = parse_args()

    assessment = load_json(
        args.input_assessment
    )

    (
        analyzer,
        provider_name,
        model_name,
    ) = build_analyzer(args)

    report = analyze_assessment(
        assessment,
        analyzer,
        provider_name=provider_name,
        model_name=model_name,
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
        f"Provider: {provider_name}"
    )

    print(
        f"Model: {model_name}"
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
