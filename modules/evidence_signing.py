#!/usr/bin/env python3

import base64
import hashlib
from copy import deepcopy

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

try:
    from modules.execution_evidence import (
        canonical_manifest_payload,
        calculate_manifest_hash,
        verify_manifest_integrity,
    )
except ModuleNotFoundError:
    from execution_evidence import (
        canonical_manifest_payload,
        calculate_manifest_hash,
        verify_manifest_integrity,
    )


SIGNATURE_ALGORITHM = "ed25519"


def generate_ed25519_keypair():
    """
    Generate an in-memory Ed25519 key pair.

    Keys are not written to disk.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key


def public_key_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_fingerprint(public_key):
    """
    Return a stable SHA-256 fingerprint for key identification.
    """
    return hashlib.sha256(
        public_key_bytes(public_key)
    ).hexdigest()


def sign_execution_manifest(
    manifest,
    private_key,
):
    """
    Return a signed copy of an execution evidence manifest.

    The original manifest is not mutated.
    """
    signed = deepcopy(manifest)

    # Ensure integrity represents the unsigned core payload.
    signed.pop("provenance", None)

    signed["integrity"] = {
        "algorithm": "sha256",
        "sha256": calculate_manifest_hash(signed),
    }

    payload = canonical_manifest_payload(signed)

    signature = private_key.sign(payload)

    public_key = private_key.public_key()

    signed["provenance"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_fingerprint": public_key_fingerprint(
            public_key
        ),
        "signature": base64.b64encode(
            signature
        ).decode("ascii"),
    }

    return signed


def verify_manifest_signature(
    manifest,
    public_key,
):
    provenance = manifest.get("provenance")

    if not provenance:
        return False

    if (
        provenance.get("algorithm")
        != SIGNATURE_ALGORITHM
    ):
        return False

    expected_fingerprint = (
        public_key_fingerprint(public_key)
    )

    if (
        provenance.get("key_fingerprint")
        != expected_fingerprint
    ):
        return False

    encoded_signature = provenance.get(
        "signature"
    )

    if not encoded_signature:
        return False

    try:
        signature = base64.b64decode(
            encoded_signature,
            validate=True,
        )
    except Exception:
        return False

    payload = canonical_manifest_payload(
        manifest
    )

    try:
        public_key.verify(
            signature,
            payload,
        )
    except InvalidSignature:
        return False

    return True


def verify_signed_manifest(
    manifest,
    public_key,
):
    """
    Require both SHA-256 integrity and Ed25519 signature
    verification to succeed.
    """
    return (
        verify_manifest_integrity(manifest)
        and verify_manifest_signature(
            manifest,
            public_key,
        )
    )
