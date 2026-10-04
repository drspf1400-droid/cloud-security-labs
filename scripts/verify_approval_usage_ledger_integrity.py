#!/usr/bin/env python3

import argparse
import json
import sys

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from modules.approval_usage_ledger import (
    ApprovalUsageLedgerError,
    verify_approval_usage_ledger_integrity,
)


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INTEGRITY_MISMATCH = 7


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Verify externally pinned approval "
            "usage ledger integrity."
        )
    )

    parser.add_argument(
        "--ledger",
        required=True,
    )

    parser.add_argument(
        "--expected-sha256",
        required=True,
    )

    parser.add_argument(
        "--output",
    )

    return parser.parse_args()


def write_result(path, value):
    if path is None:
        return

    output = Path(path)

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        json.dumps(
            value,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )


def main():
    args = parse_args()

    try:
        ledger = json.loads(
            Path(
                args.ledger
            ).read_text(
                encoding="utf-8"
            )
        )

        result = (
            verify_approval_usage_ledger_integrity(
                ledger,
                args.expected_sha256,
            )
        )

        write_result(
            args.output,
            result,
        )

        if not result["valid"]:
            print(
                "Approval usage ledger "
                "integrity: FAILED"
            )

            print(
                "Expected SHA-256:",
                result[
                    "expected_sha256"
                ],
            )

            print(
                "Actual SHA-256:",
                result[
                    "actual_sha256"
                ],
            )

            return (
                EXIT_INTEGRITY_MISMATCH
            )

        print(
            "Approval usage ledger "
            "integrity: VERIFIED"
        )

        print(
            "Ledger ID:",
            result["ledger_id"],
        )

        print(
            "SHA-256:",
            result["actual_sha256"],
        )

        return EXIT_OK

    except (
        FileNotFoundError,
        json.JSONDecodeError,
        ApprovalUsageLedgerError,
        OSError,
    ) as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )

        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
