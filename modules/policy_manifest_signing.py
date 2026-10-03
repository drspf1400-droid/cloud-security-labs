#!/usr/bin/env python3

import base64
import hashlib
import json
from copy import deepcopy

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


SIGNATURE_ALGORITHM = "ed25519"
FINGERPRINT_ALGORITHM = "sha256"


def canonical_manifest_bytes(manifest):
    """
    Canonicalize only the unsigned manifest content.

    Signature/provenance metadata is excluded from the
    signed payload so verification is deterministic.
    """

    source = deepcopy(manifest)

    source.pop("signature", None)

    return json.dumps(
        source,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def public_key_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_fingerprint(public_key):
    return hashlib.sha256(
        public_key_bytes(public_key)
    ).hexdigest()


def public_key_to_base64(public_key):
    return base64.b64encode(
        public_key_bytes(public_key)
    ).decode("ascii")


def public_key_from_base64(value):
    raw = base64.b64decode(
        value.encode("ascii"),
        validate=True,
    )

    return Ed25519PublicKey.from_public_bytes(
        raw
    )


def sign_policy_manifest(
    manifest,
    private_key,
    *,
    signer_id,
    key_id,
):
    """
    Sign a policy integrity manifest.

    The private key is used only in memory and is
    never embedded in the returned document.
    """

    if not isinstance(
        private_key,
        Ed25519PrivateKey,
    ):
        raise TypeError(
            "private_key must be an "
            "Ed25519PrivateKey"
        )

    if not signer_id:
        raise ValueError(
            "signer_id is required"
        )

    if not key_id:
        raise ValueError(
            "key_id is required"
        )

    signed = deepcopy(manifest)

    signed.pop("signature", None)

    public_key = private_key.public_key()

    signature = private_key.sign(
        canonical_manifest_bytes(signed)
    )

    signed["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "signer_id": signer_id,
        "key_id": key_id,
        "key_fingerprint": (
            public_key_fingerprint(
                public_key
            )
        ),
        "value": base64.b64encode(
            signature
        ).decode("ascii"),
    }

    return signed


def verify_policy_manifest_signature(
    signed_manifest,
    public_key,
):
    """
    Verify manifest authenticity using an expected
    Ed25519 public key.
    """

    source = deepcopy(
        signed_manifest
    )

    signature_block = source.get(
        "signature"
    )

    if not isinstance(
        signature_block,
        dict,
    ):
        return {
            "valid": False,
            "status": "unsigned",
            "reason": (
                "Policy manifest has no "
                "signature block"
            ),
        }

    if (
        signature_block.get("algorithm")
        != SIGNATURE_ALGORITHM
    ):
        return {
            "valid": False,
            "status": "unsupported_algorithm",
            "reason": (
                "Unsupported manifest signature "
                "algorithm"
            ),
        }

    expected_fingerprint = (
        public_key_fingerprint(
            public_key
        )
    )

    actual_fingerprint = (
        signature_block.get(
            "key_fingerprint"
        )
    )

    if (
        actual_fingerprint
        != expected_fingerprint
    ):
        return {
            "valid": False,
            "status": "key_mismatch",
            "reason": (
                "Manifest signer fingerprint does "
                "not match the trusted public key"
            ),
            "expected_fingerprint": (
                expected_fingerprint
            ),
            "actual_fingerprint": (
                actual_fingerprint
            ),
        }

    try:
        signature = base64.b64decode(
            signature_block["value"].encode(
                "ascii"
            ),
            validate=True,
        )
    except (
        KeyError,
        ValueError,
        TypeError,
    ):
        return {
            "valid": False,
            "status": "invalid_signature_encoding",
            "reason": (
                "Manifest signature is not valid "
                "base64"
            ),
        }

    try:
        public_key.verify(
            signature,
            canonical_manifest_bytes(
                source
            ),
        )
    except InvalidSignature:
        return {
            "valid": False,
            "status": "invalid_signature",
            "reason": (
                "Manifest signature verification "
                "failed"
            ),
            "key_fingerprint": (
                expected_fingerprint
            ),
        }

    return {
        "valid": True,
        "status": "verified",
        "reason": (
            "Policy manifest signature is valid"
        ),
        "signer_id": (
            signature_block.get(
                "signer_id"
            )
        ),
        "key_id": (
            signature_block.get(
                "key_id"
            )
        ),
        "key_fingerprint": (
            expected_fingerprint
        ),
    }
