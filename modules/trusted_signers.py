#!/usr/bin/env python3

import base64
from copy import deepcopy
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

try:
    from modules.evidence_signing import (
        public_key_bytes,
        public_key_fingerprint,
        verify_signed_manifest,
    )
except ModuleNotFoundError:
    from evidence_signing import (
        public_key_bytes,
        public_key_fingerprint,
        verify_signed_manifest,
    )


REGISTRY_VERSION = "1.0"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def create_registry():
    return {
        "registry_version": REGISTRY_VERSION,
        "signers": {},
        "audit_trail": [],
    }


def encode_public_key(public_key):
    return base64.b64encode(
        public_key_bytes(public_key)
    ).decode("ascii")


def decode_public_key(encoded_key):
    raw = base64.b64decode(
        encoded_key,
        validate=True,
    )

    return Ed25519PublicKey.from_public_bytes(raw)


def append_registry_audit(
    registry,
    *,
    timestamp,
    action,
    signer_id,
    key_id,
    fingerprint,
    details=None,
):
    registry.setdefault(
        "audit_trail",
        [],
    ).append({
        "timestamp": timestamp,
        "action": action,
        "signer_id": signer_id,
        "key_id": key_id,
        "key_fingerprint": fingerprint,
        "details": details or {},
    })


def register_signer_key(
    registry,
    *,
    signer_id,
    key_id,
    public_key,
    registered_at=None,
):
    result = deepcopy(registry)

    if registered_at is None:
        registered_at = utc_now()

    fingerprint = public_key_fingerprint(
        public_key
    )

    signers = result.setdefault(
        "signers",
        {},
    )

    if fingerprint in signers:
        raise ValueError(
            "Signer key is already registered."
        )

    signers[fingerprint] = {
        "signer_id": signer_id,
        "key_id": key_id,
        "algorithm": "ed25519",
        "public_key": encode_public_key(
            public_key
        ),
        "status": "active",
        "registered_at": registered_at,
        "revoked_at": None,
        "revocation_reason": None,
    }

    append_registry_audit(
        result,
        timestamp=registered_at,
        action="signer_key_registered",
        signer_id=signer_id,
        key_id=key_id,
        fingerprint=fingerprint,
    )

    return result


def revoke_signer_key(
    registry,
    fingerprint,
    *,
    reason,
    revoked_at=None,
):
    result = deepcopy(registry)

    signers = result.get("signers", {})

    if fingerprint not in signers:
        raise KeyError(
            "Signer key is not registered."
        )

    if revoked_at is None:
        revoked_at = utc_now()

    record = signers[fingerprint]

    if record.get("status") == "revoked":
        raise ValueError(
            "Signer key is already revoked."
        )

    record["status"] = "revoked"
    record["revoked_at"] = revoked_at
    record["revocation_reason"] = reason

    append_registry_audit(
        result,
        timestamp=revoked_at,
        action="signer_key_revoked",
        signer_id=record["signer_id"],
        key_id=record["key_id"],
        fingerprint=fingerprint,
        details={
            "reason": reason,
        },
    )

    return result


def rotate_signer_key(
    registry,
    *,
    signer_id,
    old_fingerprint,
    new_key_id,
    new_public_key,
    rotated_at=None,
):
    if rotated_at is None:
        rotated_at = utc_now()

    signers = registry.get(
        "signers",
        {},
    )

    old_record = signers.get(
        old_fingerprint
    )

    if old_record is None:
        raise KeyError(
            "Previous signer key is not registered."
        )

    if old_record.get(
        "signer_id"
    ) != signer_id:
        raise ValueError(
            "Previous key does not belong "
            "to this signer."
        )

    result = revoke_signer_key(
        registry,
        old_fingerprint,
        reason="Key rotation",
        revoked_at=rotated_at,
    )

    result = register_signer_key(
        result,
        signer_id=signer_id,
        key_id=new_key_id,
        public_key=new_public_key,
        registered_at=rotated_at,
    )

    new_fingerprint = public_key_fingerprint(
        new_public_key
    )

    append_registry_audit(
        result,
        timestamp=rotated_at,
        action="signer_key_rotated",
        signer_id=signer_id,
        key_id=new_key_id,
        fingerprint=new_fingerprint,
        details={
            "old_fingerprint": old_fingerprint,
            "new_fingerprint": new_fingerprint,
        },
    )

    return result


def verify_trusted_manifest(
    manifest,
    registry,
):
    provenance = manifest.get(
        "provenance",
        {},
    )

    fingerprint = provenance.get(
        "key_fingerprint"
    )

    if not fingerprint:
        return {
            "accepted": False,
            "trusted": False,
            "signature_valid": False,
            "status": "unsigned",
            "reason": (
                "Manifest does not contain "
                "signer provenance."
            ),
            "signer_id": None,
            "key_id": None,
            "key_fingerprint": None,
        }

    signer = (
        registry
        .get("signers", {})
        .get(fingerprint)
    )

    if signer is None:
        return {
            "accepted": False,
            "trusted": False,
            "signature_valid": False,
            "status": "unknown",
            "reason": (
                "Signing key is not present "
                "in the trusted registry."
            ),
            "signer_id": None,
            "key_id": None,
            "key_fingerprint": fingerprint,
        }

    if signer.get("status") != "active":
        return {
            "accepted": False,
            "trusted": False,
            "signature_valid": False,
            "status": signer.get(
                "status",
                "unknown",
            ),
            "reason": "Signing key is not active.",
            "signer_id": signer.get("signer_id"),
            "key_id": signer.get("key_id"),
            "key_fingerprint": fingerprint,
        }

    try:
        public_key = decode_public_key(
            signer["public_key"]
        )
    except Exception:
        return {
            "accepted": False,
            "trusted": False,
            "signature_valid": False,
            "status": "invalid_registry_key",
            "reason": (
                "Trusted registry contains "
                "an invalid public key."
            ),
            "signer_id": signer.get("signer_id"),
            "key_id": signer.get("key_id"),
            "key_fingerprint": fingerprint,
        }

    signature_valid = verify_signed_manifest(
        manifest,
        public_key,
    )

    if not signature_valid:
        return {
            "accepted": False,
            "trusted": True,
            "signature_valid": False,
            "status": "invalid_signature",
            "reason": (
                "Signer is trusted, but the "
                "manifest signature is invalid."
            ),
            "signer_id": signer.get("signer_id"),
            "key_id": signer.get("key_id"),
            "key_fingerprint": fingerprint,
        }

    return {
        "accepted": True,
        "trusted": True,
        "signature_valid": True,
        "status": "trusted",
        "reason": (
            "Manifest signature is valid and "
            "the signer key is trusted."
        ),
        "signer_id": signer.get("signer_id"),
        "key_id": signer.get("key_id"),
        "key_fingerprint": fingerprint,
    }
