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


def parse_timestamp(value):
    if not value:
        raise ValueError("Timestamp is required.")

    parsed = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if parsed.tzinfo is None:
        raise ValueError(
            "Timestamp must include timezone information."
        )

    return parsed


def verify_historical_trust(
    manifest,
    registry,
):
    """
    Verify a signed manifest against the signer trust
    state at the time the manifest was created.

    A key revoked later may still validate evidence
    created before the revocation time.
    """
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
            "trusted_at_signing_time": False,
            "signature_valid": False,
            "status": "unsigned",
            "reason": (
                "Manifest does not contain signer provenance."
            ),
        }

    signer = (
        registry
        .get("signers", {})
        .get(fingerprint)
    )

    if signer is None:
        return {
            "accepted": False,
            "trusted_at_signing_time": False,
            "signature_valid": False,
            "status": "unknown",
            "reason": (
                "Signing key is not present "
                "in the trusted registry."
            ),
        }

    try:
        evidence_time = parse_timestamp(
            manifest.get("created_at")
        )

        registered_at = parse_timestamp(
            signer.get("registered_at")
        )

        revoked_at = None

        if signer.get("revoked_at"):
            revoked_at = parse_timestamp(
                signer["revoked_at"]
            )

    except (ValueError, TypeError):
        return {
            "accepted": False,
            "trusted_at_signing_time": False,
            "signature_valid": False,
            "status": "invalid_timestamp",
            "reason": (
                "Manifest or registry contains "
                "an invalid trust timestamp."
            ),
        }

    try:
        public_key = decode_public_key(
            signer["public_key"]
        )
    except Exception:
        return {
            "accepted": False,
            "trusted_at_signing_time": False,
            "signature_valid": False,
            "status": "invalid_registry_key",
            "reason": (
                "Trusted registry contains "
                "an invalid public key."
            ),
        }

    signature_valid = verify_signed_manifest(
        manifest,
        public_key,
    )

    if not signature_valid:
        return {
            "accepted": False,
            "trusted_at_signing_time": False,
            "signature_valid": False,
            "status": "invalid_signature",
            "reason": (
                "Manifest signature is invalid."
            ),
        }

    if evidence_time < registered_at:
        return {
            "accepted": False,
            "trusted_at_signing_time": False,
            "signature_valid": True,
            "status": "before_registration",
            "reason": (
                "Manifest predates signer key registration."
            ),
        }

    if (
        revoked_at is not None
        and evidence_time >= revoked_at
    ):
        return {
            "accepted": False,
            "trusted_at_signing_time": False,
            "signature_valid": True,
            "status": "revoked_at_signing_time",
            "reason": (
                "Signer key was revoked when "
                "the manifest was created."
            ),
        }

    return {
        "accepted": True,
        "trusted_at_signing_time": True,
        "signature_valid": True,
        "status": "historically_trusted",
        "reason": (
            "Manifest signature is valid and "
            "the signer key was trusted at "
            "the manifest creation time."
        ),
        "signer_id": signer.get("signer_id"),
        "key_id": signer.get("key_id"),
        "key_fingerprint": fingerprint,
    }


def signer_lifecycle(
    registry,
    fingerprint,
):
    """
    Return signer-key state and related registry
    audit events without mutating the registry.
    """
    signer = (
        registry
        .get("signers", {})
        .get(fingerprint)
    )

    events = []

    for event in registry.get(
        "audit_trail",
        [],
    ):
        details = event.get(
            "details",
            {},
        )

        if (
            event.get("key_fingerprint")
            == fingerprint
            or details.get("old_fingerprint")
            == fingerprint
            or details.get("new_fingerprint")
            == fingerprint
        ):
            events.append(
                deepcopy(event)
            )

    return {
        "signer": deepcopy(signer),
        "audit_events": events,
    }


def evaluate_manifest_trust(
    manifest,
    registry,
):
    """
    Compare current trust with historical trust.

    Effective acceptance rules:

    - Currently active + valid signature:
      accepted using current trust.
    - Currently revoked but historically trusted:
      accepted using historical trust.
    - Invalid/unknown/untrusted at signing time:
      rejected.
    """
    current = verify_trusted_manifest(
        manifest,
        registry,
    )

    historical = verify_historical_trust(
        manifest,
        registry,
    )

    fingerprint = (
        manifest
        .get("provenance", {})
        .get("key_fingerprint")
    )

    lifecycle = signer_lifecycle(
        registry,
        fingerprint,
    )

    if current.get("accepted"):
        effective = {
            "accepted": True,
            "basis": "current_trust",
            "reason": (
                "Signer is currently trusted "
                "and the signature is valid."
            ),
        }

    elif historical.get("accepted"):
        effective = {
            "accepted": True,
            "basis": "historical_trust",
            "reason": (
                "Signer is no longer currently trusted, "
                "but was trusted when the evidence "
                "was created."
            ),
        }

    else:
        effective = {
            "accepted": False,
            "basis": "rejected",
            "reason": (
                "Evidence is not valid under either "
                "current or historical trust."
            ),
        }

    return {
        "key_fingerprint": fingerprint,
        "current_trust": current,
        "historical_trust": historical,
        "effective_trust": effective,
        "signer_lifecycle": lifecycle,
    }
