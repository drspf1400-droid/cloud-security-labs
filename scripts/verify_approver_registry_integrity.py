#!/usr/bin/env python3

import argparse
import json
import sys

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(ROOT),
    )


from modules.approver_trust_registry import (
    approver_registry_fingerprint,
)


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INTEGRITY_INVALID = 7


def load_json(path):
    return json.loads(
        Path(path).read_text(
            encoding="utf-8"
        )
    )


def write_result(path, result):
    if not path:
        return

    output = Path(path)

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        json.dumps(
            result,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Verify approver trust registry "
            "integrity"
        )
    )

    parser.add_argument(
        "--registry",
        required=True,
    )

    parser.add_argument(
        "--expected-sha256",
        required=True,
    )

    parser.add_argument(
        "--output",
    )

    return parser


def main():
    args = build_parser().parse_args()

    try:
        registry = load_json(
            args.registry
        )

        expected = (
            args.expected_sha256
            .strip()
            .lower()
        )

        if (
            len(expected) != 64
            or any(
                char not in "0123456789abcdef"
                for char in expected
            )
        ):
            raise ValueError(
                "Expected SHA-256 must be "
                "64 hexadecimal characters"
            )

        actual = (
            approver_registry_fingerprint(
                registry
            )
        )

        valid = actual == expected

        result = {
            "registry_integrity": {
                "valid": valid,
                "expected_fingerprint": (
                    expected
                ),
                "actual_fingerprint": (
                    actual
                ),
            },
            "integrity_ok": valid,
        }

        write_result(
            args.output,
            result,
        )

        if not valid:
            print(
                "Approver registry integrity: "
                "FAILED"
            )

            return EXIT_INTEGRITY_INVALID

        print(
            "Approver registry integrity: PASSED"
        )

        print(
            "Registry SHA-256: "
            f"{actual}"
        )

        return EXIT_OK

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )

        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
