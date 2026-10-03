#!/usr/bin/env python3

import base64
import hashlib
import json

from copy import deepcopy
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from modules.policy_manifest_signing import (
    public_key_fingerprint,
)

from modules.rotation_approval import (
    parse_timestamp,
    verify_rotation_approval,
)


REGISTRY_VERSION = "1.0"


class ApproverTrustRegistryError(ValueError):
    pass


def canonical_registry_bytes(registry):
    return json.dumps(
        registry,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def approver_registry_fingerprint(registry):
    return hashlib.sha256(
        canonical_registry_bytes(
            registry
        )
    ).hexdigest()


def create_approver_registry(
    *,
    created_at,
    registry_id=None,
):
    parse_timestamp(created_at)

    if registry_id is None:
        registry_id = (
            "APPROVER-TRUST-REGISTRY-"
            + str(uuid4())
        )

    return {
        "registry_version": (
            REGISTRY_VERSION
        ),
        "registry_id": registry_id,
        "created_at": created_at,
        "updated_at": created_at,
        "approvers": [],
    }


def _load_public_key(public_key_b64):
    try:
        raw = base64.b64decode(
            public_key_b64.encode("ascii"),
            validate=True,
        )

        return (
            Ed25519PublicKey
            .from_public_bytes(raw)
        )

    except Exception as exc:
        raise ApproverTrustRegistryError(
            "Invalid Ed25519 public key"
        ) from exc


def register_approver(
    registry,
    *,
    approver_id,
    key_id,
    public_key_b64,
    registered_at,
):
    if not approver_id:
        raise ApproverTrustRegistryError(
            "approver_id is required"
        )

    if not key_id:
        raise ApproverTrustRegistryError(
            "key_id is required"
        )

    parse_timestamp(
        registered_at
    )

    source = deepcopy(
        registry
    )

    public_key = _load_public_key(
        public_key_b64
    )

    fingerprint = (
        public_key_fingerprint(
            public_key
        )
    )

    for entry in source.get(
        "approvers",
        [],
    ):
        if (
            entry.get(
                "key_fingerprint"
            )
            == fingerprint
        ):
            raise ApproverTrustRegistryError(
                "Approver key is already "
                "registered"
            )

    source.setdefault(
        "approvers",
        [],
    ).append(
        {
            "approver_id": approver_id,
            "key_id": key_id,
            "algorithm": "ed25519",
            "public_key_b64": (
                public_key_b64
            ),
            "key_fingerprint": (
                fingerprint
            ),
            "status": "active",
            "registered_at": (
                registered_at
            ),
            "revoked_at": None,
            "revocation_reason": None,
        }
    )

    source["updated_at"] = (
        registered_at
    )

    return source


def revoke_approver_key(
    registry,
    key_fingerprint,
    *,
    revoked_at,
    reason="revoked",
):
    parse_timestamp(
        revoked_at
    )

    source = deepcopy(
        registry
    )

    target = None

    for entry in source.get(
        "approvers",
        [],
    ):
        if (
            entry.get(
                "key_fingerprint"
            )
            == key_fingerprint
        ):
            target = entry
            break

    if target is None:
        raise ApproverTrustRegistryError(
            "Approver key not found"
        )

    if target.get("status") != "active":
        raise ApproverTrustRegistryError(
            "Approver key is not active"
        )

    registered = parse_timestamp(
        target["registered_at"]
    )

    revoked = parse_timestamp(
        revoked_at
    )

    if revoked <= registered:
        raise ApproverTrustRegistryError(
            "revoked_at must be after "
            "registered_at"
        )

    target["status"] = "revoked"
    target["revoked_at"] = revoked_at
    target["revocation_reason"] = reason

    source["updated_at"] = (
        revoked_at
    )

    return source


def evaluate_approver_trust(
    registry,
    *,
    approver_id,
    key_fingerprint,
    at_time,
):
    approval_time = parse_timestamp(
        at_time
    )

    entry = None

    for candidate in registry.get(
        "approvers",
        [],
    ):
        if (
            candidate.get(
                "approver_id"
            )
            == approver_id
            and candidate.get(
                "key_fingerprint"
            )
            == key_fingerprint
        ):
            entry = candidate
            break

    if entry is None:
        return {
            "accepted": False,
            "basis": "untrusted_approver",
        }

    registered_at = parse_timestamp(
        entry["registered_at"]
    )

    if approval_time < registered_at:
        return {
            "accepted": False,
            "basis": (
                "key_not_yet_trusted"
            ),
            "entry": deepcopy(entry),
        }

    if entry.get("status") == "active":
        return {
            "accepted": True,
            "basis": "active_trust",
            "entry": deepcopy(entry),
        }

    if entry.get("status") == "revoked":
        revoked_at = entry.get(
            "revoked_at"
        )

        if not revoked_at:
            return {
                "accepted": False,
                "basis": (
                    "invalid_registry_entry"
                ),
                "entry": deepcopy(entry),
            }

        revocation_time = (
            parse_timestamp(
                revoked_at
            )
        )

        if approval_time < revocation_time:
            return {
                "accepted": True,
                "basis": (
                    "historical_trust"
                ),
                "entry": deepcopy(entry),
            }

        return {
            "accepted": False,
            "basis": (
                "revoked_at_approval_time"
            ),
            "entry": deepcopy(entry),
        }

    return {
        "accepted": False,
        "basis": "invalid_registry_status",
        "entry": deepcopy(entry),
    }


def verify_rotation_approval_with_registry(
    plan,
    approval,
    registry,
):
    if not isinstance(approval, dict):
        return {
            "valid": False,
            "status": "invalid_approval",
        }

    approved_at = approval.get(
        "approved_at"
    )

    if not approved_at:
        return {
            "valid": False,
            "status": (
                "invalid_approval_timestamp"
            ),
        }

    try:
        parse_timestamp(
            approved_at
        )
    except Exception:
        return {
            "valid": False,
            "status": (
                "invalid_approval_timestamp"
            ),
        }

    approved_by = approval.get(
        "approved_by"
    )

    if not approved_by:
        return {
            "valid": False,
            "status": (
                "untrusted_approver"
            ),
        }

    key_block = approval.get(
        "approver_key",
        {},
    )

    key_fingerprint = key_block.get(
        "key_fingerprint"
    )

    if not key_fingerprint:
        return {
            "valid": False,
            "status": (
                "untrusted_approver"
            ),
        }

    trust = evaluate_approver_trust(
        registry,
        approver_id=approval.get(
            "approved_by"
        ),
        key_fingerprint=key_block.get(
            "key_fingerprint"
        ),
        at_time=approval.get(
            "approved_at"
        ),
    )

    if not trust.get(
        "accepted"
    ):
        return {
            "valid": False,
            "status": trust.get(
                "basis"
            ),
            "trust": trust,
        }

    entry = trust["entry"]

    trusted_key = _load_public_key(
        entry["public_key_b64"]
    )

    verification = (
        verify_rotation_approval(
            plan,
            approval,
            trusted_public_key=(
                trusted_key
            ),
        )
    )

    if not verification.get(
        "valid"
    ):
        return verification

    result = deepcopy(
        verification
    )

    result["trust_basis"] = (
        trust["basis"]
    )

    result["approver_id"] = (
        entry["approver_id"]
    )

    result["approver_key_id"] = (
        entry["key_id"]
    )

    return result
