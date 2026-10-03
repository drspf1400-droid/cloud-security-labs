#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from modules.security_gate_policy import (
    SecurityGatePolicyError,
    load_security_gate_policy,
)

from modules.security_policy_integrity import (
    evaluate_policy_drift,
)


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DRIFT = 3


ENVIRONMENTS = (
    "lab",
    "staging",
    "production",
)


def load_json(path):
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            f"File does not exist: {path}"
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


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Verify Security Gate Policy integrity "
            "and detect policy drift."
        )
    )

    parser.add_argument(
        "--policy-dir",
        default=(
            "policies/security-gates"
        ),
        help=(
            "Directory containing environment "
            "security gate policies"
        ),
    )

    parser.add_argument(
        "--manifest",
        default=(
            "policies/security-gates/"
            "trusted-manifest.json"
        ),
        help=(
            "Trusted policy integrity manifest"
        ),
    )

    parser.add_argument(
        "--output",
        help=(
            "Optional path for machine-readable "
            "integrity result JSON"
        ),
    )

    return parser.parse_args()


def main():
    args = parse_args()

    try:
        policies = {}

        for environment in ENVIRONMENTS:
            loaded = load_security_gate_policy(
                environment,
                policy_dir=args.policy_dir,
            )

            policies[environment] = (
                loaded["document"]
            )

        manifest = load_json(
            args.manifest
        )

        result = evaluate_policy_drift(
            policies,
            manifest,
        )

        if args.output:
            output_path = Path(
                args.output
            )

            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            output_path.write_text(
                json.dumps(
                    result,
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
        return EXIT_ERROR

    print(
        "Policy integrity: "
        + (
            "OK"
            if result["integrity_ok"]
            else "DRIFT DETECTED"
        )
    )

    print(
        "Trusted manifest: "
        f"{result.get('manifest_id')}"
    )

    summary = result["summary"]

    print(
        "Summary: "
        f"unchanged={summary['unchanged']} "
        f"drifted={summary['drifted']} "
        f"missing={summary['missing']} "
        f"untrusted={summary['untrusted']}"
    )

    for item in result["results"]:
        print(
            f"{item['environment']}: "
            f"{item['status']}"
        )

    if result["integrity_ok"]:
        return EXIT_OK

    return EXIT_DRIFT


if __name__ == "__main__":
    raise SystemExit(main())
