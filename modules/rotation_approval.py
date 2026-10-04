#!/usr/bin/env python3

import base64
import hashlib
import json

from copy import deepcopy
from datetime import datetime
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from modules.policy_manifest_signing import (
    public_key_fingerprint,
    public_key_to_base64,
)


APPROVAL_VERSION = "1.0"

APPROVAL_SCOPES = {
    "rotation",
    "execute",
    "promote",
}


class RotationApprovalError(ValueError):
    pass


def parse_timestamp(value):
    try:
        parsed = datetime.fromisoformat(
            value
        )
    except (
        TypeError,
        ValueError,
    ) as exc:
        raise RotationApprovalError(
            f"Invalid timestamp: {value}"
        ) from exc

    if parsed.tzinfo is None:
        raise RotationApprovalError(
            "Timestamp must include timezone"
        )

    return parsed


def canonical_plan_bytes(plan):
    """
    Deterministic representation of a rotation plan.
    """
    return json.dumps(
        plan,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def rotation_plan_fingerprint(plan):
    """
    SHA-256 fingerprint of the complete rotation plan.
    """
    return hashlib.sha256(
        canonical_plan_bytes(plan)
    ).hexdigest()


def canonical_approval_bytes(approval):
    """
    Canonicalize approval content while excluding
    the signature block.
    """
    source = deepcopy(approval)

    source.pop(
        "signature",
        None,
    )

    return json.dumps(
        source,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_rotation_approval(
    plan,
    private_key,
    *,
    initiated_by,
    approved_by,
    approved_at,
    approval_scope="rotation",
    approval_id=None,
):
    """
    Create a signed human approval artifact bound to
    one exact rotation plan.
    """

    if not isinstance(
        private_key,
        Ed25519PrivateKey,
    ):
        raise RotationApprovalError(
            "private_key must be an "
            "Ed25519PrivateKey"
        )

    if not initiated_by:
        raise RotationApprovalError(
            "initiated_by is required"
        )

    plan_initiator = plan.get(
        "initiated_by"
    )

    if not plan_initiator:
        raise RotationApprovalError(
            "Rotation plan has no initiated_by"
        )

    if initiated_by != plan_initiator:
        raise RotationApprovalError(
            "Approval initiator does not match "
            "the rotation plan initiator"
        )

    if not approved_by:
        raise RotationApprovalError(
            "approved_by is required"
        )

    if initiated_by == approved_by:
        raise RotationApprovalError(
            "Separation of duties violation: "
            "initiator and approver must differ"
        )

    if approval_scope not in APPROVAL_SCOPES:
        raise RotationApprovalError(
            "Unsupported approval_scope: "
            f"{approval_scope}"
        )

    parse_timestamp(
        approved_at
    )

    if (
        plan.get("status")
        != "planned"
    ):
        raise RotationApprovalError(
            "Only a planned rotation can be approved"
        )

    if not plan.get(
        "requires_approval"
    ):
        raise RotationApprovalError(
            "Rotation plan does not require approval"
        )

    rotation_id = plan.get(
        "rotation_id"
    )

    if not rotation_id:
        raise RotationApprovalError(
            "Rotation plan has no rotation_id"
        )

    if approval_id is None:
        approval_id = str(
            uuid4()
        )

    public_key = (
        private_key.public_key()
    )

    approval = {
        "approval_version": (
            APPROVAL_VERSION
        ),
        "approval_id": approval_id,
        "approval_scope": approval_scope,
        "rotation_id": rotation_id,
        "plan_sha256": (
            rotation_plan_fingerprint(
                plan
            )
        ),
        "decision": "approved",
        "initiated_by": initiated_by,
        "approved_by": approved_by,
        "approved_at": approved_at,
        "approver_key": {
            "algorithm": "ed25519",
            "key_fingerprint": (
                public_key_fingerprint(
                    public_key
                )
            ),
            "public_key_b64": (
                public_key_to_base64(
                    public_key
                )
            ),
        },
    }

    signature = private_key.sign(
        canonical_approval_bytes(
            approval
        )
    )

    approval["signature"] = {
        "algorithm": "ed25519",
        "value": (
            base64.b64encode(
                signature
            ).decode("ascii")
        ),
    }

    return approval


def verify_rotation_approval(
    plan,
    approval,
    *,
    trusted_public_key=None,
    required_scope=None,
):
    """
    Verify:
    - exact plan binding
    - rotation ID
    - separation of duties
    - approver key fingerprint
    - Ed25519 signature
    """

    plan_source = deepcopy(
        plan
    )

    approval_source = deepcopy(
        approval
    )

    if (
        required_scope is not None
        and required_scope not in APPROVAL_SCOPES
    ):
        raise RotationApprovalError(
            "Unsupported required_scope: "
            f"{required_scope}"
        )

    if (
        approval_source.get(
            "approval_version"
        )
        != APPROVAL_VERSION
    ):
        return {
            "valid": False,
            "status": (
                "unsupported_approval_version"
            ),
        }

    if (
        approval_source.get(
            "decision"
        )
        != "approved"
    ):
        return {
            "valid": False,
            "status": "not_approved",
        }

    approval_scope = (
        approval_source.get(
            "approval_scope",
            "rotation",
        )
    )

    if approval_scope not in APPROVAL_SCOPES:
        return {
            "valid": False,
            "status": "invalid_approval_scope",
        }

    if (
        required_scope is not None
        and approval_scope != required_scope
    ):
        return {
            "valid": False,
            "status": "approval_scope_mismatch",
            "approval_scope": approval_scope,
            "required_scope": required_scope,
        }

    if (
        approval_source.get(
            "rotation_id"
        )
        != plan_source.get(
            "rotation_id"
        )
    ):
        return {
            "valid": False,
            "status": "rotation_id_mismatch",
        }

    actual_plan_sha = (
        rotation_plan_fingerprint(
            plan_source
        )
    )

    if (
        approval_source.get(
            "plan_sha256"
        )
        != actual_plan_sha
    ):
        return {
            "valid": False,
            "status": "plan_mismatch",
            "actual_plan_sha256": (
                actual_plan_sha
            ),
            "approved_plan_sha256": (
                approval_source.get(
                    "plan_sha256"
                )
            ),
        }

    initiated_by = (
        approval_source.get(
            "initiated_by"
        )
    )

    if (
        initiated_by
        != plan_source.get(
            "initiated_by"
        )
    ):
        return {
            "valid": False,
            "status": "initiator_mismatch",
        }

    approved_by = (
        approval_source.get(
            "approved_by"
        )
    )

    if (
        not initiated_by
        or not approved_by
        or initiated_by == approved_by
    ):
        return {
            "valid": False,
            "status": (
                "separation_of_duties_violation"
            ),
        }

    try:
        parse_timestamp(
            approval_source.get(
                "approved_at"
            )
        )
    except RotationApprovalError:
        return {
            "valid": False,
            "status": "invalid_approval_timestamp",
        }

    key_block = approval_source.get(
        "approver_key",
        {},
    )

    signature_block = (
        approval_source.get(
            "signature",
            {}
        )
    )

    if (
        key_block.get("algorithm")
        != "ed25519"
        or signature_block.get(
            "algorithm"
        )
        != "ed25519"
    ):
        return {
            "valid": False,
            "status": "unsupported_algorithm",
        }

    try:
        embedded_key = (
            Ed25519PublicKey.from_public_bytes(
                base64.b64decode(
                    key_block[
                        "public_key_b64"
                    ].encode(
                        "ascii"
                    ),
                    validate=True,
                )
            )
        )
    except Exception:
        return {
            "valid": False,
            "status": "invalid_public_key",
        }

    embedded_fingerprint = (
        public_key_fingerprint(
            embedded_key
        )
    )

    if (
        embedded_fingerprint
        != key_block.get(
            "key_fingerprint"
        )
    ):
        return {
            "valid": False,
            "status": (
                "approver_key_fingerprint_mismatch"
            ),
        }

    verification_key = (
        trusted_public_key
        if trusted_public_key is not None
        else embedded_key
    )

    if (
        public_key_fingerprint(
            verification_key
        )
        != embedded_fingerprint
    ):
        return {
            "valid": False,
            "status": "untrusted_approver_key",
        }

    try:
        signature = base64.b64decode(
            signature_block[
                "value"
            ].encode("ascii"),
            validate=True,
        )

        verification_key.verify(
            signature,
            canonical_approval_bytes(
                approval_source
            ),
        )

    except (
        KeyError,
        ValueError,
        InvalidSignature,
    ):
        return {
            "valid": False,
            "status": "invalid_signature",
        }

    return {
        "valid": True,
        "status": "verified",
        "rotation_id": (
            approval_source[
                "rotation_id"
            ]
        ),
        "plan_sha256": actual_plan_sha,
        "initiated_by": initiated_by,
        "approved_by": approved_by,
        "approved_at": (
            approval_source[
                "approved_at"
            ]
        ),
        "approval_scope": (
            approval_scope
        ),
        "approver_key_fingerprint": (
            embedded_fingerprint
        ),
    }
