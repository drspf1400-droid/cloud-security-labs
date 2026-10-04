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

from modules.security_gate_policy import (
    load_security_gate_policy,
)

from modules.approval_usage_ledger import (
    approval_usage_ledger_fingerprint,
    create_approval_usage_ledger,
    validate_approval_usage_ledger,
    verify_approval_usage_ledger_integrity,
)

from modules.rotation_approval import (
    RotationApprovalError,
    sign_rotation_approval,
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


def load_or_create_approval_usage_ledger(
    path,
    *,
    created_at,
):
    if path is None:
        return None

    ledger_path = Path(path)

    if ledger_path.exists():
        ledger = load_json(
            ledger_path
        )

        validate_approval_usage_ledger(
            ledger
        )

        return ledger

    return create_approval_usage_ledger(
        created_at=created_at,
    )


def load_verified_or_initialize_approval_usage_ledger(
    path,
    *,
    created_at,
    expected_sha256=None,
    initialize=False,
):
    ledger_path = Path(path)

    if ledger_path.exists():
        if initialize:
            raise ValueError(
                "--initialize-approval-usage-ledger "
                "cannot be used for an existing ledger"
            )

        ledger = load_json(
            ledger_path
        )

        validate_approval_usage_ledger(
            ledger
        )

        if not expected_sha256:
            raise ValueError(
                "--approval-usage-ledger-sha256 "
                "is required for an existing ledger"
            )

        verification = (
            verify_approval_usage_ledger_integrity(
                ledger,
                expected_sha256,
            )
        )

        if not verification["valid"]:
            raise ValueError(
                "Approval usage ledger "
                "integrity mismatch"
            )

        return ledger, verification

    if not initialize:
        raise FileNotFoundError(
            "Approval usage ledger does not exist; "
            "use --initialize-approval-usage-ledger "
            "for explicit bootstrap"
        )

    if expected_sha256:
        raise ValueError(
            "--approval-usage-ledger-sha256 "
            "cannot be supplied while initializing"
        )

    ledger = create_approval_usage_ledger(
        created_at=created_at,
    )

    fingerprint = (
        approval_usage_ledger_fingerprint(
            ledger
        )
    )

    return ledger, {
        "valid": True,
        "status": "ledger_initialized",
        "expected_sha256": None,
        "actual_sha256": fingerprint,
        "ledger_id": ledger["ledger_id"],
    }


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


def load_public_key(path):
    from cryptography.hazmat.primitives.serialization import (
        load_pem_public_key,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

    key_data = Path(
        path
    ).read_bytes()

    key = load_pem_public_key(
        key_data
    )

    if not isinstance(
        key,
        Ed25519PublicKey,
    ):
        raise ValueError(
            "Approver public key must be Ed25519"
        )

    return key


def build_parser():
    parser = argparse.ArgumentParser(

        allow_abbrev=False,description=(
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
        "--initiated-by",
        required=True,
        help=(
            "Identity of the operator initiating "
            "the rotation"
        ),
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

    approve_parser = subparsers.add_parser(
        "approve",
        help=(
            "Create a cryptographically signed "
            "human approval artifact"
        ),
    )

    approve_parser.add_argument(
        "--plan",
        required=True,
    )

    approve_parser.add_argument(
        "--approver-private-key",
        required=True,
    )

    approve_parser.add_argument(
        "--approved-by",
        required=True,
    )

    approve_parser.add_argument(
        "--approved-at",
        required=True,
    )

    approve_parser.add_argument(
        "--scope",
        choices=(
            "rotation",
            "execute",
            "promote",
        ),
        default="rotation",
        help=(
            "Action this approval authorizes"
        ),
    )

    approve_parser.add_argument(
        "--approval-id",
    )

    approve_parser.add_argument(
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
        "--approval",
        required=True,
        action="append",
        metavar="FILE",
        help=(
            "Signed rotation approval artifact. "
            "Repeat for multiple approvers."
        ),
    )

    execute_parser.add_argument(
        "--required-approvals",
        type=int,
        default=1,
        help=(
            "Minimum number of unique trusted "
            "approvals required"
        ),
    )

    execute_parser.add_argument(
        "--environment",
        choices=(
            "lab",
            "staging",
            "production",
        ),
        default="production",
        help=(
            "Security policy environment. "
            "Defaults to production."
        ),
    )

    execute_parser.add_argument(
        "--approver-registry",
        required=True,
        help=(
            "Trusted approver registry"
        ),
    )

    execute_parser.add_argument(
        "--approval-usage-ledger",
        help=(
            "Persistent one-time approval "
            "usage ledger"
        ),
    )

    execute_parser.add_argument(
        "--approval-usage-ledger-sha256",
        help=(
            "Externally trusted SHA-256 pin "
            "for the existing usage ledger"
        ),
    )

    execute_parser.add_argument(
        "--initialize-approval-usage-ledger",
        action="store_true",
        help=(
            "Explicitly initialize a new usage "
            "ledger when none exists"
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
        "--plan",
        required=True,
        help=(
            "Original approved rotation plan"
        ),
    )

    promote_parser.add_argument(
        "--approval",
        required=True,
        action="append",
        metavar="FILE",
        help=(
            "Signed rotation approval artifact. "
            "Repeat for multiple approvers."
        ),
    )

    promote_parser.add_argument(
        "--required-approvals",
        type=int,
        default=1,
        help=(
            "Minimum number of unique trusted "
            "approvals required"
        ),
    )

    promote_parser.add_argument(
        "--environment",
        choices=(
            "lab",
            "staging",
            "production",
        ),
        default="production",
        help=(
            "Security policy environment. "
            "Defaults to production."
        ),
    )

    promote_parser.add_argument(
        "--approver-registry",
        required=True,
        help=(
            "Trusted approver registry"
        ),
    )

    promote_parser.add_argument(
        "--approval-usage-ledger",
        help=(
            "Persistent one-time approval "
            "usage ledger"
        ),
    )

    promote_parser.add_argument(
        "--approval-usage-ledger-sha256",
        help=(
            "Externally trusted SHA-256 pin "
            "for the existing usage ledger"
        ),
    )

    promote_parser.add_argument(
        "--initialize-approval-usage-ledger",
        action="store_true",
        help=(
            "Explicitly initialize a new usage "
            "ledger when none exists"
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
        initiated_by=args.initiated_by,
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
        "Initiated by: "
        f"{plan['initiated_by']}"
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


def command_approve(args):
    plan = load_json(
        args.plan
    )

    private_key = load_private_key(
        args.approver_private_key
    )

    approval = sign_rotation_approval(
        plan,
        private_key,
        initiated_by=(
            plan.get("initiated_by")
        ),
        approved_by=args.approved_by,
        approved_at=args.approved_at,
        approval_scope=args.scope,
        approval_id=args.approval_id,
    )

    write_json(
        args.output,
        approval,
    )

    print("Signed rotation approval created")
    print(
        "Approval ID: "
        f"{approval['approval_id']}"
    )
    print(
        "Rotation ID: "
        f"{approval['rotation_id']}"
    )
    print(
        "Initiated by: "
        f"{approval['initiated_by']}"
    )
    print(
        "Approved by: "
        f"{approval['approved_by']}"
    )
    print(
        "Approval scope: "
        f"{approval['approval_scope']}"
    )
    print(
        "Plan SHA-256: "
        f"{approval['plan_sha256']}"
    )
    print(
        "Approval: "
        f"{args.output}"
    )

    return EXIT_OK


def command_execute(args):
    plan = load_json(
        args.plan
    )

    approvals = [
        load_json(path)
        for path in args.approval
    ]

    approver_registry = load_json(
        args.approver_registry
    )

    environment_policy = (
        load_security_gate_policy(
            args.environment
        )
    )

    policy_required_approvals = (
        environment_policy[
            "rotation_approval"
        ]["required_approvals"]
    )

    policy_required_roles = (
        environment_policy[
            "rotation_approval"
        ]["required_roles"]
    )

    policy_require_distinct_role_holders = (
        environment_policy[
            "rotation_approval"
        ]["require_distinct_role_holders"]
    )

    policy_max_approval_age_seconds = (
        environment_policy[
            "rotation_approval"
        ]["max_approval_age_seconds"]
    )

    policy_require_action_scope = (
        environment_policy[
            "rotation_approval"
        ]["require_action_scope"]
    )

    policy_required_scope = (
        "execute"
        if policy_require_action_scope
        else None
    )

    policy_require_replay_protection = (
        environment_policy[
            "rotation_approval"
        ]["require_replay_protection"]
    )

    if (
        policy_require_replay_protection
        and not args.approval_usage_ledger
    ):
        raise ValueError(
            "--approval-usage-ledger is required "
            "when replay protection is enabled"
        )

    policy_require_ledger_integrity_pin = (
        environment_policy[
            "rotation_approval"
        ]["require_ledger_integrity_pin"]
    )

    ledger_integrity = None

    if policy_require_ledger_integrity_pin:
        approval_usage_ledger, ledger_integrity = (
            load_verified_or_initialize_approval_usage_ledger(
                args.approval_usage_ledger,
                created_at=plan["rotated_at"],
                expected_sha256=(
                    args.approval_usage_ledger_sha256
                ),
                initialize=(
                    args.initialize_approval_usage_ledger
                ),
            )
        )

    else:
        approval_usage_ledger = (
            load_or_create_approval_usage_ledger(
                args.approval_usage_ledger,
                created_at=(
                    plan["rotated_at"]
                ),
            )
            if args.approval_usage_ledger
            else None
        )

    effective_required_approvals = max(
        policy_required_approvals,
        args.required_approvals,
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
        approvals=approvals,
        approver_registry=(
            approver_registry
        ),
        required_approvals=(
            effective_required_approvals
        ),
        required_roles=(
            policy_required_roles
        ),
        require_distinct_role_holders=(
            policy_require_distinct_role_holders
        ),
        max_approval_age_seconds=(
            policy_max_approval_age_seconds
        ),
        required_scope=(
            policy_required_scope
        ),
        approval_usage_ledger=(
            approval_usage_ledger
        ),
        require_replay_protection=(
            policy_require_replay_protection
        ),
    )

    output_ledger_sha256 = None

    if policy_require_replay_protection:
        write_json(
            args.approval_usage_ledger,
            result[
                "approval_usage_ledger"
            ],
        )

        output_ledger_sha256 = (
            approval_usage_ledger_fingerprint(
                result[
                    "approval_usage_ledger"
                ]
            )
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
        "approval_quorum": (
            result["approval_quorum"]
        ),
        "policy_context": {
            "environment": (
                args.environment
            ),
            "policy_required_approvals": (
                policy_required_approvals
            ),
            "policy_required_roles": list(
                policy_required_roles
            ),
            "require_distinct_role_holders": (
                policy_require_distinct_role_holders
            ),
            "max_approval_age_seconds": (
                policy_max_approval_age_seconds
            ),
            "require_action_scope": (
                policy_require_action_scope
            ),
            "required_scope": (
                policy_required_scope
            ),
            "require_replay_protection": (
                policy_require_replay_protection
            ),
            "require_ledger_integrity_pin": (
                policy_require_ledger_integrity_pin
            ),
            "effective_required_approvals": (
                effective_required_approvals
            ),
        },
        "rotated_at": (
            result["rotated_at"]
        ),
        "old_signer": (
            result["old_signer"]
        ),
        "new_signer": (
            result["new_signer"]
        ),
        "approval_usage_ledger_integrity": {
            "input": ledger_integrity,
            "output_sha256": (
                output_ledger_sha256
            ),
        },
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
        f"{result['approved_by']}"
    )
    print(
        "New signer: "
        f"{result['new_signer']['key_id']}"
    )
    print(
        "Verification: "
        f"{summary['verification']['basis']}"
    )
    if output_ledger_sha256:
        print(
            "Approval usage ledger SHA-256: "
            f"{output_ledger_sha256}"
        )

    print(f"Output: {output_dir}")

    return EXIT_OK


def command_promote(args):
    plan = load_json(
        args.plan
    )

    approvals = [
        load_json(path)
        for path in args.approval
    ]

    approver_registry = load_json(
        args.approver_registry
    )

    environment_policy = (
        load_security_gate_policy(
            args.environment
        )
    )

    policy_required_approvals = (
        environment_policy[
            "rotation_approval"
        ]["required_approvals"]
    )

    policy_required_roles = (
        environment_policy[
            "rotation_approval"
        ]["required_roles"]
    )

    policy_require_distinct_role_holders = (
        environment_policy[
            "rotation_approval"
        ]["require_distinct_role_holders"]
    )

    policy_max_approval_age_seconds = (
        environment_policy[
            "rotation_approval"
        ]["max_approval_age_seconds"]
    )

    policy_require_action_scope = (
        environment_policy[
            "rotation_approval"
        ]["require_action_scope"]
    )

    policy_required_scope = (
        "promote"
        if policy_require_action_scope
        else None
    )

    policy_require_replay_protection = (
        environment_policy[
            "rotation_approval"
        ]["require_replay_protection"]
    )

    if (
        policy_require_replay_protection
        and not args.approval_usage_ledger
    ):
        raise ValueError(
            "--approval-usage-ledger is required "
            "when replay protection is enabled"
        )

    policy_require_ledger_integrity_pin = (
        environment_policy[
            "rotation_approval"
        ]["require_ledger_integrity_pin"]
    )

    ledger_integrity = None

    if policy_require_ledger_integrity_pin:
        approval_usage_ledger, ledger_integrity = (
            load_verified_or_initialize_approval_usage_ledger(
                args.approval_usage_ledger,
                created_at=(
                    args.promoted_at
                    or plan["rotated_at"]
                ),
                expected_sha256=(
                    args.approval_usage_ledger_sha256
                ),
                initialize=(
                    args.initialize_approval_usage_ledger
                ),
            )
        )

    else:
        approval_usage_ledger = (
            load_or_create_approval_usage_ledger(
                args.approval_usage_ledger,
                created_at=(
                    args.promoted_at
                    or plan["rotated_at"]
                ),
            )
            if args.approval_usage_ledger
            else None
        )

    effective_required_approvals = max(
        policy_required_approvals,
        args.required_approvals,
    )

    audit = promote_policy_rotation(
        plan=plan,
        approvals=approvals,
        approver_registry=(
            approver_registry
        ),
        required_approvals=(
            effective_required_approvals
        ),
        required_roles=(
            policy_required_roles
        ),
        require_distinct_role_holders=(
            policy_require_distinct_role_holders
        ),
        max_approval_age_seconds=(
            policy_max_approval_age_seconds
        ),
        required_scope=(
            policy_required_scope
        ),
        approval_usage_ledger=(
            approval_usage_ledger
        ),
        require_replay_protection=(
            policy_require_replay_protection
        ),
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
        audit_path=None,
        promoted_by=args.promoted_by,
        promoted_at=args.promoted_at,
    )

    updated_usage_ledger = (
        audit.pop(
            "approval_usage_ledger",
            None,
        )
    )

    output_ledger_sha256 = None

    if policy_require_replay_protection:
        write_json(
            args.approval_usage_ledger,
            updated_usage_ledger,
        )

        output_ledger_sha256 = (
            approval_usage_ledger_fingerprint(
                updated_usage_ledger
            )
        )

    audit[
        "approval_usage_ledger_integrity"
    ] = {
        "input": ledger_integrity,
        "output_sha256": (
            output_ledger_sha256
        ),
        "required": (
            policy_require_ledger_integrity_pin
        ),
    }

    write_json(
        args.audit_output,
        audit,
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
    if output_ledger_sha256:
        print(
            "Approval usage ledger SHA-256: "
            f"{output_ledger_sha256}"
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

        if args.command == "approve":
            return command_approve(args)

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
        RotationApprovalError,
        OSError,
    ) as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )

        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
