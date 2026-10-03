#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from modules.policy_manifest_signing import (
    public_key_from_base64,
    verify_policy_manifest_signature,
)

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
EXIT_SIGNATURE_INVALID = 4

DEFAULT_PUBLIC_KEY_FILE = (
    "policies/security-gates/"
    "trusted-manifest-public-key.b64"
)


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


def decode_public_key(value):
    try:
        return public_key_from_base64(
            value.strip()
        )
    except Exception as exc:
        raise ValueError(
            "Invalid trusted Ed25519 public key"
        ) from exc


def load_public_key(path):
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            f"Trusted public key does not exist: {path}"
        )

    value = path.read_text(
        encoding="utf-8"
    )

    return decode_public_key(value)


def write_result(path, result):
    if not path:
        return

    output_path = Path(path)

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


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Authenticate the trusted Security Gate "
            "Policy manifest and detect policy drift."
        )
    )

    parser.add_argument(
        "--policy-dir",
        default="policies/security-gates",
    )

    parser.add_argument(
        "--manifest",
        default=(
            "policies/security-gates/"
            "trusted-manifest.json"
        ),
    )

    trust_anchor = (
        parser.add_mutually_exclusive_group()
    )

    trust_anchor.add_argument(
        "--public-key-file",
        help=(
            "Trusted Ed25519 public key file. "
            "Uses repository key when omitted."
        ),
    )

    trust_anchor.add_argument(
        "--public-key-b64",
        help=(
            "Trusted Ed25519 public key supplied "
            "externally as base64"
        ),
    )

    parser.add_argument(
        "--output",
        help=(
            "Optional machine-readable result JSON"
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

        if args.public_key_b64:
            public_key = decode_public_key(
                args.public_key_b64
            )

            trust_anchor_source = (
                "external_value"
            )
        else:
            public_key_path = (
                args.public_key_file
                or DEFAULT_PUBLIC_KEY_FILE
            )

            public_key = load_public_key(
                public_key_path
            )

            trust_anchor_source = (
                "repository_file"
            )

        authenticity = (
            verify_policy_manifest_signature(
                manifest,
                public_key,
            )
        )

        if not authenticity["valid"]:
            result = {
                "manifest_authenticity": (
                    authenticity
                ),
                "trust_anchor": {
                    "source": (
                        trust_anchor_source
                    ),
                    "key_fingerprint": (
                        authenticity.get(
                            "expected_fingerprint"
                        )
                        or authenticity.get(
                            "key_fingerprint"
                        )
                    ),
                },
                "integrity_ok": False,
            }

            write_result(
                args.output,
                result,
            )

            print(
                "Manifest authenticity: FAILED"
            )

            print(
                "Signature status: "
                f"{authenticity.get('status')}"
            )

            return EXIT_SIGNATURE_INVALID

        result = evaluate_policy_drift(
            policies,
            manifest,
        )

        result["manifest_authenticity"] = (
            authenticity
        )

        result["trust_anchor"] = {
            "source": trust_anchor_source,
            "key_fingerprint": (
                authenticity.get(
                    "key_fingerprint"
                )
            ),
        }

        write_result(
            args.output,
            result,
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

    print("Manifest authenticity: VERIFIED")

    print(
        "Trust anchor source: "
        f"{trust_anchor_source}"
    )

    print(
        "Signer: "
        f"{authenticity.get('signer_id')}"
    )

    print(
        "Signing key: "
        f"{authenticity.get('key_id')}"
    )

    print(
        "Policy integrity: "
        + (
            "OK"
            if result["integrity_ok"]
            else "DRIFT DETECTED"
        )
    )

    summary = result["summary"]

    print(
        "Summary: "
        f"unchanged={summary['unchanged']} "
        f"drifted={summary['drifted']} "
        f"missing={summary['missing']} "
        f"untrusted={summary['untrusted']}"
    )

    if result["integrity_ok"]:
        return EXIT_OK

    return EXIT_DRIFT


if __name__ == "__main__":
    raise SystemExit(main())
