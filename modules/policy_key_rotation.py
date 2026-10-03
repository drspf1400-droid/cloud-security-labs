#!/usr/bin/env python3

from copy import deepcopy

from modules.rotation_approval import verify_rotation_approval
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from modules.policy_manifest_signing import (
    public_key_fingerprint,
    public_key_to_base64,
    sign_policy_manifest,
)

from modules.policy_signer_registry import (
    evaluate_policy_manifest_trust,
    get_policy_signer,
    parse_timestamp,
    rotate_policy_signer,
)


ROTATION_VERSION = "1.0"


class PolicyKeyRotationError(ValueError):
    pass


def plan_policy_key_rotation(
    manifest,
    registry,
    *,
    old_fingerprint,
    new_private_key,
    new_signer_id,
    new_key_id,
    rotated_at,
    initiated_by=None,
    rotation_id=None,
    new_manifest_id=None,
):
    """
    Build a controlled key-rotation plan.

    Planning performs trust and lifecycle checks but
    does not modify the registry or manifest.
    """

    if not isinstance(
        new_private_key,
        Ed25519PrivateKey,
    ):
        raise PolicyKeyRotationError(
            "new_private_key must be an "
            "Ed25519PrivateKey"
        )

    parse_timestamp(rotated_at)

    if not initiated_by:
        raise PolicyKeyRotationError(
            "initiated_by is required"
        )

    manifest_source = deepcopy(manifest)
    registry_source = deepcopy(registry)

    trust = evaluate_policy_manifest_trust(
        manifest_source,
        registry_source,
    )

    if not trust[
        "current_trust"
    ]["accepted"]:
        raise PolicyKeyRotationError(
            "Current manifest is not trusted by "
            "an active signer"
        )

    current_fingerprint = trust.get(
        "key_fingerprint"
    )

    if (
        current_fingerprint
        != old_fingerprint
    ):
        raise PolicyKeyRotationError(
            "Requested old signer does not match "
            "the current manifest signer"
        )

    old_signer = get_policy_signer(
        registry_source,
        old_fingerprint,
    )

    if old_signer is None:
        raise PolicyKeyRotationError(
            "Old signing key is not registered"
        )

    if old_signer.get("status") != "active":
        raise PolicyKeyRotationError(
            "Old signing key is not active"
        )

    new_public_key = (
        new_private_key.public_key()
    )

    new_fingerprint = (
        public_key_fingerprint(
            new_public_key
        )
    )

    if new_fingerprint == old_fingerprint:
        raise PolicyKeyRotationError(
            "New signing key must differ from "
            "the current signing key"
        )

    if get_policy_signer(
        registry_source,
        new_fingerprint,
    ) is not None:
        raise PolicyKeyRotationError(
            "New signing key is already registered"
        )

    if rotation_id is None:
        rotation_id = str(uuid4())

    if new_manifest_id is None:
        new_manifest_id = str(uuid4())

    return {
        "rotation_version": ROTATION_VERSION,
        "rotation_id": rotation_id,
        "status": "planned",
        "requires_approval": True,
        "initiated_by": initiated_by,
        "rotated_at": rotated_at,
        "source_manifest_id": (
            manifest_source.get(
                "manifest_id"
            )
        ),
        "new_manifest_id": new_manifest_id,
        "old_signer": {
            "signer_id": (
                old_signer.get(
                    "signer_id"
                )
            ),
            "key_id": (
                old_signer.get(
                    "key_id"
                )
            ),
            "key_fingerprint": (
                old_fingerprint
            ),
        },
        "new_signer": {
            "signer_id": new_signer_id,
            "key_id": new_key_id,
            "key_fingerprint": (
                new_fingerprint
            ),
            "public_key_b64": (
                public_key_to_base64(
                    new_public_key
                )
            ),
        },
    }


def execute_policy_key_rotation(
    plan,
    manifest,
    registry,
    new_private_key,
    *,
    approval,
    trusted_approver_public_key,
):
    """
    Execute an approved rotation plan.

    Returns new registry, re-signed manifest and
    machine-readable audit evidence.
    """

    if not isinstance(
        new_private_key,
        Ed25519PrivateKey,
    ):
        raise PolicyKeyRotationError(
            "new_private_key must be an "
            "Ed25519PrivateKey"
        )

    approval_verification = (
        verify_rotation_approval(
            plan,
            approval,
            trusted_public_key=(
                trusted_approver_public_key
            ),
        )
    )

    if not approval_verification.get(
        "valid"
    ):
        raise PolicyKeyRotationError(
            "Signed rotation approval "
            "verification failed: "
            f"{approval_verification.get('status')}"
        )

    approved_by = (
        approval_verification[
            "approved_by"
        ]
    )

    plan_source = deepcopy(plan)
    manifest_source = deepcopy(manifest)
    registry_source = deepcopy(registry)

    if (
        plan_source.get("status")
        != "planned"
    ):
        raise PolicyKeyRotationError(
            "Rotation plan is not executable"
        )

    rotated_at = plan_source.get(
        "rotated_at"
    )

    parse_timestamp(rotated_at)

    old_signer = plan_source[
        "old_signer"
    ]

    new_signer = plan_source[
        "new_signer"
    ]

    actual_new_fingerprint = (
        public_key_fingerprint(
            new_private_key.public_key()
        )
    )

    if (
        actual_new_fingerprint
        != new_signer[
            "key_fingerprint"
        ]
    ):
        raise PolicyKeyRotationError(
            "New private key does not match "
            "the approved rotation plan"
        )

    current_trust = (
        evaluate_policy_manifest_trust(
            manifest_source,
            registry_source,
        )
    )

    if not current_trust[
        "current_trust"
    ]["accepted"]:
        raise PolicyKeyRotationError(
            "Current manifest trust changed "
            "after rotation planning"
        )

    if (
        current_trust.get(
            "key_fingerprint"
        )
        != old_signer[
            "key_fingerprint"
        ]
    ):
        raise PolicyKeyRotationError(
            "Current manifest signer changed "
            "after rotation planning"
        )

    rotated_registry = (
        rotate_policy_signer(
            registry_source,
            old_signer[
                "key_fingerprint"
            ],
            new_signer_id=(
                new_signer["signer_id"]
            ),
            new_key_id=(
                new_signer["key_id"]
            ),
            new_public_key_b64=(
                new_signer[
                    "public_key_b64"
                ]
            ),
            rotated_at=rotated_at,
            reason=(
                "controlled_policy_key_rotation"
            ),
        )
    )

    unsigned_manifest = deepcopy(
        manifest_source
    )

    unsigned_manifest.pop(
        "signature",
        None,
    )

    unsigned_manifest[
        "manifest_id"
    ] = plan_source[
        "new_manifest_id"
    ]

    unsigned_manifest[
        "created_at"
    ] = rotated_at

    signed_manifest = (
        sign_policy_manifest(
            unsigned_manifest,
            new_private_key,
            signer_id=(
                new_signer["signer_id"]
            ),
            key_id=(
                new_signer["key_id"]
            ),
        )
    )

    new_trust = (
        evaluate_policy_manifest_trust(
            signed_manifest,
            rotated_registry,
        )
    )

    if not new_trust[
        "current_trust"
    ]["accepted"]:
        raise PolicyKeyRotationError(
            "Rotated manifest failed "
            "post-rotation trust verification"
        )

    audit_event = {
        "action": (
            "controlled_policy_key_rotation"
        ),
        "rotation_id": (
            plan_source["rotation_id"]
        ),
        "timestamp": rotated_at,
        "approved_by": approved_by,
        "source_manifest_id": (
            plan_source[
                "source_manifest_id"
            ]
        ),
        "new_manifest_id": (
            plan_source[
                "new_manifest_id"
            ]
        ),
        "old_key_fingerprint": (
            old_signer[
                "key_fingerprint"
            ]
        ),
        "new_key_fingerprint": (
            new_signer[
                "key_fingerprint"
            ]
        ),
        "verification_basis": (
            new_trust[
                "effective_trust"
            ]["basis"]
        ),
    }

    return {
        "rotation_version": (
            ROTATION_VERSION
        ),
        "rotation_id": (
            plan_source["rotation_id"]
        ),
        "status": "completed",
        "approved_by": approved_by,
        "rotated_at": rotated_at,
        "old_signer": deepcopy(
            old_signer
        ),
        "new_signer": deepcopy(
            new_signer
        ),
        "registry": rotated_registry,
        "manifest": signed_manifest,
        "verification": new_trust,
        "audit_event": audit_event,
    }
