#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from modules.policy_key_rotation import (
    PolicyKeyRotationError,
    execute_policy_key_rotation,
    plan_policy_key_rotation,
)

from modules.policy_rotation_promotion import (
    PolicyRotationPromotionError,
    promote_policy_rotation,
)


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_APPROVAL_REQUIRED = 6


DEFAULT_MANIFEST = (
    "policies/security-gates/"
    "trusted-manifest.json"
)

DEFAULT_REGISTRY = (
    "policies/security-gates/"
    "trusted-policy-signers.json"
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
        )
        + "\n",
        encoding="utf-8",
    )


def load_private_key(path):
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            f"Private key does not exist: {path}"
        )

    key = serialization.load_pem_private_key(
        path.read_bytes(),
        password=None,
    )

    if not isinstance(
        key,
        Ed25519PrivateKey,
    ):
        raise ValueError(
            "Private key must be Ed25519"
        )

    return key


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Plan and execute controlled "
            "policy-signing key rotation."
        )
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    plan_parser = subparsers.add_parser(
        "plan",
        help="Create a rotation plan",
    )

    plan_parser.add_argument(
        "--manifest",
        default=DEFAULT_MANIFEST,
    )

    plan_parser.add_argument(
        "--registry",
        default=DEFAULT_REGISTRY,
    )

    plan_parser.add_argument(
        "--new-private-key",
        required=True,
    )

    plan_parser.add_argument(
        "--new-signer-id",
        required=True,
    )

    plan_parser.add_argument(
        "--new-key-id",
        required=True,
    )

    plan_parser.add_argument(
        "--rotated-at",
        required=True,
    )

    plan_parser.add_argument(
        "--rotation-id",
    )

    plan_parser.add_argument(
        "--new-manifest-id",
    )

    plan_parser.add_argument(
        "--output",
        required=True,
    )

    execute_parser = subparsers.add_parser(
        "execute",
        help=(
            "Execute an explicitly approved "
            "rotation plan"
        ),
    )

    execute_parser.add_argument(
        "--plan",
        required=True,
    )

    execute_parser.add_argument(
        "--manifest",
        default=DEFAULT_MANIFEST,
    )

    execute_parser.add_argument(
        "--registry",
        default=DEFAULT_REGISTRY,
    )

    execute_parser.add_argument(
        "--new-private-key",
        required=True,
    )

    execute_parser.add_argument(
        "--approved-by",
        required=True,
    )

    execute_parser.add_argument(
        "--approve",
        action="store_true",
        help=(
            "Explicitly authorize execution "
            "of the reviewed rotation plan"
        ),
    )

    execute_parser.add_argument(
        "--output-dir",
        required=True,
    )

    promote_parser = subparsers.add_parser(
        "promote",
        help=(
            "Promote a reviewed rotation candidate "
            "with backup and rollback protection"
        ),
    )

    promote_parser.add_argument(
        "--current-manifest",
        default=DEFAULT_MANIFEST,
    )

    promote_parser.add_argument(
        "--current-registry",
        default=DEFAULT_REGISTRY,
    )

    promote_parser.add_argument(
        "--candidate-manifest",
        required=True,
    )

    promote_parser.add_argument(
        "--candidate-registry",
        required=True,
    )

    promote_parser.add_argument(
        "--backup-dir",
        required=True,
    )

    promote_parser.add_argument(
        "--audit-output",
        required=True,
    )

    promote_parser.add_argument(
        "--promoted-by",
        required=True,
    )

    promote_parser.add_argument(
        "--promoted-at",
    )

    promote_parser.add_argument(
        "--approve",
        action="store_true",
        help=(
            "Explicitly approve promotion of "
            "the reviewed rotation candidate"
        ),
    )

    return parser


def command_plan(args):
    manifest = load_json(
        args.manifest
    )

    registry = load_json(
        args.registry
    )

    new_private_key = load_private_key(
        args.new_private_key
    )

    signature = manifest.get(
        "signature",
        {},
    )

    old_fingerprint = signature.get(
        "key_fingerprint"
    )

    if not old_fingerprint:
        raise PolicyKeyRotationError(
            "Current manifest does not contain "
            "a signer fingerprint"
        )

    plan = plan_policy_key_rotation(
        manifest,
        registry,
        old_fingerprint=old_fingerprint,
        new_private_key=new_private_key,
        new_signer_id=(
            args.new_signer_id
        ),
        new_key_id=args.new_key_id,
        rotated_at=args.rotated_at,
        rotation_id=args.rotation_id,
        new_manifest_id=(
            args.new_manifest_id
        ),
    )

    write_json(
        args.output,
        plan,
    )

    print("Policy key rotation plan created")
    print(f"Plan: {args.output}")
    print(
        "Rotation ID: "
        f"{plan['rotation_id']}"
    )
    print(
        "Old key: "
        f"{plan['old_signer']['key_id']}"
    )
    print(
        "New key: "
        f"{plan['new_signer']['key_id']}"
    )
    print("Approval required: yes")

    return EXIT_OK


def command_execute(args):
    if not args.approve:
        print(
            "ERROR: explicit --approve is required",
            file=sys.stderr,
        )

        return EXIT_APPROVAL_REQUIRED

    plan = load_json(
        args.plan
    )

    manifest = load_json(
        args.manifest
    )

    registry = load_json(
        args.registry
    )

    new_private_key = load_private_key(
        args.new_private_key
    )

    result = execute_policy_key_rotation(
        plan,
        manifest,
        registry,
        new_private_key,
        approved_by=args.approved_by,
    )

    output_dir = Path(
        args.output_dir
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    registry_path = (
        output_dir
        / "trusted-policy-signers.json"
    )

    manifest_path = (
        output_dir
        / "trusted-manifest.json"
    )

    audit_path = (
        output_dir
        / "policy-key-rotation-audit.json"
    )

    result_path = (
        output_dir
        / "policy-key-rotation-result.json"
    )

    write_json(
        registry_path,
        result["registry"],
    )

    write_json(
        manifest_path,
        result["manifest"],
    )

    write_json(
        audit_path,
        result["audit_event"],
    )

    summary = {
        "rotation_version": (
            result["rotation_version"]
        ),
        "rotation_id": (
            result["rotation_id"]
        ),
        "status": result["status"],
        "approved_by": (
            result["approved_by"]
        ),
        "rotated_at": (
            result["rotated_at"]
        ),
        "old_signer": (
            result["old_signer"]
        ),
        "new_signer": (
            result["new_signer"]
        ),
        "verification": {
            "accepted": (
                result["verification"]
                ["effective_trust"]
                ["accepted"]
            ),
            "basis": (
                result["verification"]
                ["effective_trust"]
                ["basis"]
            ),
        },
    }

    write_json(
        result_path,
        summary,
    )

    print("Policy key rotation completed")
    print(
        "Approved by: "
        f"{args.approved_by}"
    )
    print(
        "New signer: "
        f"{result['new_signer']['key_id']}"
    )
    print(
        "Verification: "
        f"{summary['verification']['basis']}"
    )
    print(f"Output: {output_dir}")

    return EXIT_OK


def command_promote(args):
    if not args.approve:
        print(
            "ERROR: explicit --approve is required",
            file=sys.stderr,
        )
        return EXIT_APPROVAL_REQUIRED

    audit = promote_policy_rotation(
        current_manifest_path=(
            args.current_manifest
        ),
        current_registry_path=(
            args.current_registry
        ),
        candidate_manifest_path=(
            args.candidate_manifest
        ),
        candidate_registry_path=(
            args.candidate_registry
        ),
        backup_dir=args.backup_dir,
        audit_path=args.audit_output,
        promoted_by=args.promoted_by,
        promoted_at=args.promoted_at,
    )

    print("Policy key rotation promoted")
    print(
        "Promoted by: "
        f"{audit['promoted_by']}"
    )
    print(
        "Old key: "
        f"{audit['old_key_fingerprint']}"
    )
    print(
        "New key: "
        f"{audit['new_key_fingerprint']}"
    )
    print(
        "New registry SHA-256: "
        f"{audit['new_registry_sha256']}"
    )
    print(
        "Old manifest trust: "
        f"{audit['old_manifest_trust_basis']}"
    )
    print(
        "Audit: "
        f"{args.audit_output}"
    )

    return EXIT_OK


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "plan":
            return command_plan(args)

        if args.command == "execute":
            return command_execute(args)

        if args.command == "promote":
            return command_promote(args)

        raise ValueError(
            f"Unsupported command: {args.command}"
        )

    except (
        FileNotFoundError,
        ValueError,
        PolicyKeyRotationError,
        PolicyRotationPromotionError,
        OSError,
    ) as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )

        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
