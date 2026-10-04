#!/usr/bin/env python3

import json
import os
import shutil
import tempfile

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from modules.approval_quorum import verify_rotation_approval_quorum

from modules.policy_signer_registry import (
    evaluate_policy_manifest_trust,
    get_policy_signer,
    policy_signer_registry_fingerprint,
)


class PolicyRotationPromotionError(ValueError):
    pass


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


def load_json(path):
    return json.loads(
        Path(path).read_text(
            encoding="utf-8"
        )
    )


def _atomic_copy(source, destination):
    source = Path(source)
    destination = Path(destination)

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )

    os.close(fd)

    temporary = Path(temporary)

    try:
        shutil.copyfile(
            source,
            temporary,
        )

        os.replace(
            temporary,
            destination,
        )

    finally:
        if temporary.exists():
            temporary.unlink()


def _write_json(path, value):
    path = Path(path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )

    os.close(fd)

    temporary = Path(temporary)

    try:
        temporary.write_text(
            json.dumps(
                value,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        os.replace(
            temporary,
            path,
        )

    finally:
        if temporary.exists():
            temporary.unlink()


def validate_rotation_candidate(
    current_manifest,
    current_registry,
    candidate_manifest,
    candidate_registry,
):
    current_manifest = deepcopy(
        current_manifest
    )

    current_registry = deepcopy(
        current_registry
    )

    candidate_manifest = deepcopy(
        candidate_manifest
    )

    candidate_registry = deepcopy(
        candidate_registry
    )

    current_trust = (
        evaluate_policy_manifest_trust(
            current_manifest,
            current_registry,
        )
    )

    if not current_trust[
        "current_trust"
    ]["accepted"]:
        raise PolicyRotationPromotionError(
            "Current trust baseline is not valid"
        )

    candidate_trust = (
        evaluate_policy_manifest_trust(
            candidate_manifest,
            candidate_registry,
        )
    )

    if not candidate_trust[
        "current_trust"
    ]["accepted"]:
        raise PolicyRotationPromotionError(
            "Candidate manifest is not "
            "currently trusted"
        )

    old_fingerprint = (
        current_trust[
            "key_fingerprint"
        ]
    )

    new_fingerprint = (
        candidate_trust[
            "key_fingerprint"
        ]
    )

    if (
        old_fingerprint
        == new_fingerprint
    ):
        raise PolicyRotationPromotionError(
            "Candidate does not rotate "
            "the signing key"
        )

    old_after_rotation = get_policy_signer(
        candidate_registry,
        old_fingerprint,
    )

    new_after_rotation = get_policy_signer(
        candidate_registry,
        new_fingerprint,
    )

    if (
        old_after_rotation is None
        or old_after_rotation.get("status")
        != "revoked"
    ):
        raise PolicyRotationPromotionError(
            "Old signer is not revoked "
            "in candidate registry"
        )

    if (
        new_after_rotation is None
        or new_after_rotation.get("status")
        != "active"
    ):
        raise PolicyRotationPromotionError(
            "New signer is not active "
            "in candidate registry"
        )

    old_historical_trust = (
        evaluate_policy_manifest_trust(
            current_manifest,
            candidate_registry,
        )
    )

    if not old_historical_trust[
        "historical_trust"
    ]["accepted"]:
        raise PolicyRotationPromotionError(
            "Old manifest does not retain "
            "historical trust"
        )

    return {
        "valid": True,
        "old_key_fingerprint": (
            old_fingerprint
        ),
        "new_key_fingerprint": (
            new_fingerprint
        ),
        "candidate_registry_sha256": (
            policy_signer_registry_fingerprint(
                candidate_registry
            )
        ),
        "candidate_trust_basis": (
            candidate_trust[
                "effective_trust"
            ]["basis"]
        ),
        "old_manifest_trust_basis": (
            old_historical_trust[
                "effective_trust"
            ]["basis"]
        ),
    }


def promote_policy_rotation(
    *,
    plan,
    approval=None,
    approvals=None,
    approver_registry,
    required_approvals=1,
    required_roles=None,
    require_distinct_role_holders=False,
    max_approval_age_seconds=None,
    current_manifest_path,
    current_registry_path,
    candidate_manifest_path,
    candidate_registry_path,
    backup_dir,
    audit_path=None,
    promoted_by,
    promoted_at=None,
):
    if approvals is None:
        approvals = (
            []
            if approval is None
            else [approval]
        )

    if promoted_at is None:
        promoted_at = utc_now()

    quorum_verification = (
        verify_rotation_approval_quorum(
            plan,
            approvals,
            approver_registry,
            required_approvals=(
                required_approvals
            ),
            required_roles=(
                required_roles
            ),
            require_distinct_role_holders=(
                require_distinct_role_holders
            ),
            max_approval_age_seconds=(
                max_approval_age_seconds
            ),
            reference_time=(
                promoted_at
                if max_approval_age_seconds
                is not None
                else None
            ),
        )
    )

    if not quorum_verification.get(
        "valid"
    ):
        raise PolicyRotationPromotionError(
            "Rotation approval quorum "
            "verification failed: "
            f"{quorum_verification.get('status')}"
        )

    if not promoted_by:
        raise PolicyRotationPromotionError(
            "promoted_by is required"
        )

    current_manifest_path = Path(
        current_manifest_path
    )

    current_registry_path = Path(
        current_registry_path
    )

    candidate_manifest_path = Path(
        candidate_manifest_path
    )

    candidate_registry_path = Path(
        candidate_registry_path
    )

    backup_dir = Path(
        backup_dir
    )

    current_manifest = load_json(
        current_manifest_path
    )

    current_registry = load_json(
        current_registry_path
    )

    candidate_manifest = load_json(
        candidate_manifest_path
    )

    candidate_registry = load_json(
        candidate_registry_path
    )

    validation = validate_rotation_candidate(
        current_manifest,
        current_registry,
        candidate_manifest,
        candidate_registry,
    )

    backup_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    manifest_backup = (
        backup_dir
        / "trusted-manifest.before-rotation.json"
    )

    registry_backup = (
        backup_dir
        / "trusted-policy-signers.before-rotation.json"
    )

    shutil.copy2(
        current_manifest_path,
        manifest_backup,
    )

    shutil.copy2(
        current_registry_path,
        registry_backup,
    )

    try:
        # Registry first is intentional:
        # the old manifest remains historically
        # trusted while the new registry is active.
        _atomic_copy(
            candidate_registry_path,
            current_registry_path,
        )

        _atomic_copy(
            candidate_manifest_path,
            current_manifest_path,
        )

    except Exception as exc:
        try:
            _atomic_copy(
                registry_backup,
                current_registry_path,
            )

            _atomic_copy(
                manifest_backup,
                current_manifest_path,
            )

        except Exception as rollback_exc:
            raise PolicyRotationPromotionError(
                "Promotion failed and rollback "
                f"also failed: {rollback_exc}"
            ) from exc

        raise PolicyRotationPromotionError(
            "Promotion failed; previous trust "
            "state was restored"
        ) from exc

    audit = {
        "action": "promote_policy_key_rotation",
        "status": "completed",
        "promoted_by": promoted_by,
        "promoted_at": promoted_at,
        "approval_quorum": {
            "status": (
                quorum_verification[
                    "status"
                ]
            ),
            "required_approvals": (
                quorum_verification[
                    "required_approvals"
                ]
            ),
            "required_roles": list(
                quorum_verification[
                    "required_roles"
                ]
            ),
            "satisfied_roles": list(
                quorum_verification[
                    "satisfied_roles"
                ]
            ),
            "missing_roles": list(
                quorum_verification[
                    "missing_roles"
                ]
            ),
            "require_distinct_role_holders": (
                quorum_verification[
                    "require_distinct_role_holders"
                ]
            ),
            "distinct_role_holders_satisfied": (
                quorum_verification[
                    "distinct_role_holders_satisfied"
                ]
            ),
            "role_assignments": deepcopy(
                quorum_verification[
                    "role_assignments"
                ]
            ),
            "distinct_role_unassigned_roles": list(
                quorum_verification[
                    "distinct_role_unassigned_roles"
                ]
            ),
            "max_approval_age_seconds": (
                quorum_verification[
                    "max_approval_age_seconds"
                ]
            ),
            "reference_time": (
                quorum_verification[
                    "reference_time"
                ]
            ),
            "expired_approval_count": (
                quorum_verification[
                    "expired_approval_count"
                ]
            ),
            "future_approval_count": (
                quorum_verification[
                    "future_approval_count"
                ]
            ),
            "valid_approval_count": (
                quorum_verification[
                    "valid_approval_count"
                ]
            ),
            "approvers": list(
                quorum_verification[
                    "approvers"
                ]
            ),
        },
        "old_key_fingerprint": (
            validation[
                "old_key_fingerprint"
            ]
        ),
        "new_key_fingerprint": (
            validation[
                "new_key_fingerprint"
            ]
        ),
        "new_registry_sha256": (
            validation[
                "candidate_registry_sha256"
            ]
        ),
        "candidate_trust_basis": (
            validation[
                "candidate_trust_basis"
            ]
        ),
        "old_manifest_trust_basis": (
            validation[
                "old_manifest_trust_basis"
            ]
        ),
        "backup_manifest": str(
            manifest_backup
        ),
        "backup_registry": str(
            registry_backup
        ),
    }

    if audit_path is not None:
        _write_json(
            audit_path,
            audit,
        )

    return audit
