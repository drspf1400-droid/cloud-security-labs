#!/usr/bin/env python3

from copy import deepcopy
from datetime import datetime, timezone
from uuid import uuid4

from modules.policy_manifest_signing import (
    public_key_fingerprint,
    public_key_from_base64,
    verify_policy_manifest_signature,
)


REGISTRY_VERSION = "1.0"


class PolicySignerRegistryError(ValueError):
    pass


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


def parse_timestamp(value):
    try:
        parsed = datetime.fromisoformat(value)
    except (
        TypeError,
        ValueError,
    ) as exc:
        raise PolicySignerRegistryError(
            f"Invalid timestamp: {value}"
        ) from exc

    if parsed.tzinfo is None:
        raise PolicySignerRegistryError(
            "Timestamp must include timezone"
        )

    return parsed


def create_policy_signer_registry(
    *,
    registry_id=None,
    created_at=None,
):
    if registry_id is None:
        registry_id = str(uuid4())

    if created_at is None:
        created_at = utc_now()

    parse_timestamp(created_at)

    return {
        "registry_version": REGISTRY_VERSION,
        "registry_id": registry_id,
        "created_at": created_at,
        "updated_at": created_at,
        "signers": [],
        "audit_trail": [],
    }


def _find_signer(
    registry,
    fingerprint,
):
    for signer in registry.get(
        "signers",
        [],
    ):
        if (
            signer.get("key_fingerprint")
            == fingerprint
        ):
            return signer

    return None


def register_policy_signer(
    registry,
    *,
    signer_id,
    key_id,
    public_key_b64,
    registered_at=None,
):
    result = deepcopy(registry)

    if registered_at is None:
        registered_at = utc_now()

    parse_timestamp(registered_at)

    public_key = public_key_from_base64(
        public_key_b64
    )

    fingerprint = (
        public_key_fingerprint(
            public_key
        )
    )

    if _find_signer(
        result,
        fingerprint,
    ):
        raise PolicySignerRegistryError(
            "Signing key is already registered"
        )

    for signer in result.get(
        "signers",
        [],
    ):
        if (
            signer.get("signer_id")
            == signer_id
            and signer.get("key_id")
            == key_id
        ):
            raise PolicySignerRegistryError(
                "signer_id/key_id pair "
                "is already registered"
            )

    signer = {
        "signer_id": signer_id,
        "key_id": key_id,
        "key_fingerprint": fingerprint,
        "public_key_b64": public_key_b64,
        "status": "active",
        "registered_at": registered_at,
        "revoked_at": None,
        "revocation_reason": None,
    }

    result.setdefault(
        "signers",
        [],
    ).append(signer)

    result.setdefault(
        "audit_trail",
        [],
    ).append(
        {
            "action": "register",
            "timestamp": registered_at,
            "signer_id": signer_id,
            "key_id": key_id,
            "key_fingerprint": fingerprint,
        }
    )

    result["updated_at"] = registered_at

    return result


def revoke_policy_signer(
    registry,
    fingerprint,
    *,
    revoked_at=None,
    reason,
):
    result = deepcopy(registry)

    if revoked_at is None:
        revoked_at = utc_now()

    revoked_time = parse_timestamp(
        revoked_at
    )

    signer = _find_signer(
        result,
        fingerprint,
    )

    if signer is None:
        raise PolicySignerRegistryError(
            "Signing key is not registered"
        )

    if signer.get("status") == "revoked":
        raise PolicySignerRegistryError(
            "Signing key is already revoked"
        )

    registered_time = parse_timestamp(
        signer["registered_at"]
    )

    if revoked_time < registered_time:
        raise PolicySignerRegistryError(
            "revoked_at cannot be before "
            "registered_at"
        )

    signer["status"] = "revoked"
    signer["revoked_at"] = revoked_at
    signer["revocation_reason"] = reason

    result.setdefault(
        "audit_trail",
        [],
    ).append(
        {
            "action": "revoke",
            "timestamp": revoked_at,
            "signer_id": signer["signer_id"],
            "key_id": signer["key_id"],
            "key_fingerprint": fingerprint,
            "reason": reason,
        }
    )

    result["updated_at"] = revoked_at

    return result


def rotate_policy_signer(
    registry,
    old_fingerprint,
    *,
    new_signer_id,
    new_key_id,
    new_public_key_b64,
    rotated_at=None,
    reason="key_rotation",
):
    if rotated_at is None:
        rotated_at = utc_now()

    result = revoke_policy_signer(
        registry,
        old_fingerprint,
        revoked_at=rotated_at,
        reason=reason,
    )

    result = register_policy_signer(
        result,
        signer_id=new_signer_id,
        key_id=new_key_id,
        public_key_b64=new_public_key_b64,
        registered_at=rotated_at,
    )

    new_public_key = (
        public_key_from_base64(
            new_public_key_b64
        )
    )

    new_fingerprint = (
        public_key_fingerprint(
            new_public_key
        )
    )

    result.setdefault(
        "audit_trail",
        [],
    ).append(
        {
            "action": "rotate",
            "timestamp": rotated_at,
            "old_key_fingerprint": (
                old_fingerprint
            ),
            "new_key_fingerprint": (
                new_fingerprint
            ),
            "new_signer_id": (
                new_signer_id
            ),
            "new_key_id": new_key_id,
        }
    )

    result["updated_at"] = rotated_at

    return result


def get_policy_signer(
    registry,
    fingerprint,
):
    signer = _find_signer(
        registry,
        fingerprint,
    )

    if signer is None:
        return None

    return deepcopy(signer)


def policy_signer_lifecycle(
    registry,
    fingerprint,
):
    signer = get_policy_signer(
        registry,
        fingerprint,
    )

    events = [
        deepcopy(event)
        for event in registry.get(
            "audit_trail",
            [],
        )
        if (
            event.get("key_fingerprint")
            == fingerprint
            or event.get(
                "old_key_fingerprint"
            )
            == fingerprint
            or event.get(
                "new_key_fingerprint"
            )
            == fingerprint
        )
    ]

    return {
        "signer": signer,
        "audit_events": events,
    }


def _manifest_signer(
    manifest,
    registry,
):
    signature = manifest.get(
        "signature",
        {},
    )

    fingerprint = signature.get(
        "key_fingerprint"
    )

    if not fingerprint:
        return None, None

    signer = _find_signer(
        registry,
        fingerprint,
    )

    return fingerprint, signer


def _verify_signer_identity(
    manifest,
    signer,
):
    signature = manifest.get(
        "signature",
        {},
    )

    if (
        signature.get("signer_id")
        != signer.get("signer_id")
    ):
        return False

    if (
        signature.get("key_id")
        != signer.get("key_id")
    ):
        return False

    return True


def verify_policy_manifest_current_trust(
    manifest,
    registry,
):
    """
    Verify whether a signed policy manifest is trusted
    under the signer's current lifecycle state.
    """

    fingerprint, signer = _manifest_signer(
        manifest,
        registry,
    )

    if fingerprint is None:
        return {
            "accepted": False,
            "status": "unsigned",
            "reason": (
                "Policy manifest has no signer "
                "fingerprint"
            ),
            "key_fingerprint": None,
            "signature_valid": False,
        }

    if signer is None:
        return {
            "accepted": False,
            "status": "unknown_signer",
            "reason": (
                "Policy manifest signer is not "
                "registered"
            ),
            "key_fingerprint": fingerprint,
            "signature_valid": False,
        }

    if not _verify_signer_identity(
        manifest,
        signer,
    ):
        return {
            "accepted": False,
            "status": "signer_metadata_mismatch",
            "reason": (
                "Manifest signer metadata does not "
                "match the trusted registry"
            ),
            "key_fingerprint": fingerprint,
            "signature_valid": False,
        }

    public_key = public_key_from_base64(
        signer["public_key_b64"]
    )

    signature_result = (
        verify_policy_manifest_signature(
            manifest,
            public_key,
        )
    )

    if not signature_result["valid"]:
        return {
            "accepted": False,
            "status": (
                signature_result["status"]
            ),
            "reason": (
                signature_result["reason"]
            ),
            "key_fingerprint": fingerprint,
            "signature_valid": False,
        }

    if signer.get("status") != "active":
        return {
            "accepted": False,
            "status": "revoked_signer",
            "reason": (
                "Signing key is not currently active"
            ),
            "key_fingerprint": fingerprint,
            "signature_valid": True,
        }

    return {
        "accepted": True,
        "status": "trusted",
        "reason": (
            "Manifest signature is valid and signer "
            "is currently active"
        ),
        "key_fingerprint": fingerprint,
        "signature_valid": True,
    }


def verify_policy_manifest_historical_trust(
    manifest,
    registry,
):
    """
    Verify trust at manifest.created_at.

    A revoked signer may remain historically trusted
    when the manifest was created after registration
    but before revocation.
    """

    fingerprint, signer = _manifest_signer(
        manifest,
        registry,
    )

    if fingerprint is None:
        return {
            "accepted": False,
            "status": "unsigned",
            "reason": (
                "Policy manifest has no signer "
                "fingerprint"
            ),
            "key_fingerprint": None,
            "signature_valid": False,
        }

    if signer is None:
        return {
            "accepted": False,
            "status": "unknown_signer",
            "reason": (
                "Policy manifest signer is not "
                "registered"
            ),
            "key_fingerprint": fingerprint,
            "signature_valid": False,
        }

    if not _verify_signer_identity(
        manifest,
        signer,
    ):
        return {
            "accepted": False,
            "status": "signer_metadata_mismatch",
            "reason": (
                "Manifest signer metadata does not "
                "match the trusted registry"
            ),
            "key_fingerprint": fingerprint,
            "signature_valid": False,
        }

    manifest_time = parse_timestamp(
        manifest.get("created_at")
    )

    registered_time = parse_timestamp(
        signer["registered_at"]
    )

    if manifest_time < registered_time:
        return {
            "accepted": False,
            "status": "before_registration",
            "reason": (
                "Manifest predates signer "
                "registration"
            ),
            "key_fingerprint": fingerprint,
            "signature_valid": False,
        }

    revoked_at = signer.get(
        "revoked_at"
    )

    if revoked_at is not None:
        revoked_time = parse_timestamp(
            revoked_at
        )

        if manifest_time >= revoked_time:
            return {
                "accepted": False,
                "status": "after_revocation",
                "reason": (
                    "Manifest was created at or "
                    "after signer revocation"
                ),
                "key_fingerprint": fingerprint,
                "signature_valid": False,
            }

    public_key = public_key_from_base64(
        signer["public_key_b64"]
    )

    signature_result = (
        verify_policy_manifest_signature(
            manifest,
            public_key,
        )
    )

    if not signature_result["valid"]:
        return {
            "accepted": False,
            "status": (
                signature_result["status"]
            ),
            "reason": (
                signature_result["reason"]
            ),
            "key_fingerprint": fingerprint,
            "signature_valid": False,
        }

    return {
        "accepted": True,
        "status": "historically_trusted",
        "reason": (
            "Manifest signature was valid during "
            "the signer's trusted lifecycle"
        ),
        "key_fingerprint": fingerprint,
        "signature_valid": True,
    }


def evaluate_policy_manifest_trust(
    manifest,
    registry,
):
    """
    Combine current and historical signer trust into
    one effective policy-manifest trust decision.
    """

    current = (
        verify_policy_manifest_current_trust(
            manifest,
            registry,
        )
    )

    historical = (
        verify_policy_manifest_historical_trust(
            manifest,
            registry,
        )
    )

    fingerprint = (
        current.get("key_fingerprint")
        or historical.get(
            "key_fingerprint"
        )
    )

    lifecycle = policy_signer_lifecycle(
        registry,
        fingerprint,
    ) if fingerprint else {
        "signer": None,
        "audit_events": [],
    }

    if current["accepted"]:
        effective = {
            "accepted": True,
            "basis": "current_trust",
            "reason": current["reason"],
        }

    elif historical["accepted"]:
        effective = {
            "accepted": True,
            "basis": "historical_trust",
            "reason": historical["reason"],
        }

    else:
        effective = {
            "accepted": False,
            "basis": "rejected",
            "reason": (
                current.get("reason")
                or historical.get("reason")
            ),
        }

    return {
        "key_fingerprint": fingerprint,
        "current_trust": current,
        "historical_trust": historical,
        "effective_trust": effective,
        "signer_lifecycle": lifecycle,
    }


def canonical_registry_bytes(registry):
    """
    Return deterministic canonical JSON bytes for
    external trust-anchor fingerprinting.
    """
    import json

    return json.dumps(
        registry,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def policy_signer_registry_fingerprint(
    registry,
):
    """
    Calculate SHA-256 over the canonical registry.
    """
    import hashlib

    return hashlib.sha256(
        canonical_registry_bytes(
            registry
        )
    ).hexdigest()
