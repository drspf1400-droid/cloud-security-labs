from copy import deepcopy

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from modules.policy_manifest_signing import (
    canonical_manifest_bytes,
    public_key_fingerprint,
    public_key_from_base64,
    public_key_to_base64,
    sign_policy_manifest,
    verify_policy_manifest_signature,
)


def sample_manifest():
    return {
        "manifest_version": "1.0",
        "manifest_id": "POLICY-MANIFEST-001",
        "created_at": (
            "2026-10-03T10:00:00+00:00"
        ),
        "algorithm": "sha256",
        "policies": {
            "production": {
                "policy_name": (
                    "production-security-gate"
                ),
                "policy_version": "1.0",
                "fingerprint": "a" * 64,
            }
        },
    }


def test_manifest_can_be_signed_and_verified():
    private_key = (
        Ed25519PrivateKey.generate()
    )

    signed = sign_policy_manifest(
        sample_manifest(),
        private_key,
        signer_id="security-policy-authority",
        key_id="policy-key-001",
    )

    result = (
        verify_policy_manifest_signature(
            signed,
            private_key.public_key(),
        )
    )

    assert result["valid"] is True
    assert result["status"] == "verified"

    assert (
        result["signer_id"]
        == "security-policy-authority"
    )

    assert (
        result["key_id"]
        == "policy-key-001"
    )


def test_modified_manifest_fails_verification():
    private_key = (
        Ed25519PrivateKey.generate()
    )

    signed = sign_policy_manifest(
        sample_manifest(),
        private_key,
        signer_id="security-policy-authority",
        key_id="policy-key-001",
    )

    signed["policies"]["production"][
        "fingerprint"
    ] = "b" * 64

    result = (
        verify_policy_manifest_signature(
            signed,
            private_key.public_key(),
        )
    )

    assert result["valid"] is False
    assert (
        result["status"]
        == "invalid_signature"
    )


def test_wrong_public_key_is_rejected():
    signing_key = (
        Ed25519PrivateKey.generate()
    )

    wrong_key = (
        Ed25519PrivateKey
        .generate()
        .public_key()
    )

    signed = sign_policy_manifest(
        sample_manifest(),
        signing_key,
        signer_id="security-policy-authority",
        key_id="policy-key-001",
    )

    result = (
        verify_policy_manifest_signature(
            signed,
            wrong_key,
        )
    )

    assert result["valid"] is False
    assert result["status"] == "key_mismatch"


def test_unsigned_manifest_is_rejected():
    key = (
        Ed25519PrivateKey
        .generate()
        .public_key()
    )

    result = (
        verify_policy_manifest_signature(
            sample_manifest(),
            key,
        )
    )

    assert result["valid"] is False
    assert result["status"] == "unsigned"


def test_public_key_round_trip():
    private_key = (
        Ed25519PrivateKey.generate()
    )

    public_key = (
        private_key.public_key()
    )

    encoded = public_key_to_base64(
        public_key
    )

    restored = public_key_from_base64(
        encoded
    )

    assert (
        public_key_fingerprint(public_key)
        == public_key_fingerprint(restored)
    )


def test_signature_metadata_contains_no_private_key():
    private_key = (
        Ed25519PrivateKey.generate()
    )

    signed = sign_policy_manifest(
        sample_manifest(),
        private_key,
        signer_id="security-policy-authority",
        key_id="policy-key-001",
    )

    block = signed["signature"]

    assert "private_key" not in block

    assert set(block) == {
        "algorithm",
        "signer_id",
        "key_id",
        "key_fingerprint",
        "value",
    }


def test_signing_does_not_mutate_manifest():
    manifest = sample_manifest()
    original = deepcopy(manifest)

    sign_policy_manifest(
        manifest,
        Ed25519PrivateKey.generate(),
        signer_id="security-policy-authority",
        key_id="policy-key-001",
    )

    assert manifest == original


def test_canonicalization_ignores_signature_block():
    manifest = sample_manifest()

    unsigned = canonical_manifest_bytes(
        manifest
    )

    signed_like = deepcopy(manifest)

    signed_like["signature"] = {
        "algorithm": "ed25519",
        "value": "anything",
    }

    assert (
        canonical_manifest_bytes(
            signed_like
        )
        == unsigned
    )


def test_committed_policy_manifest_signature_is_valid():
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]

    manifest = json.loads(
        (
            root
            / "policies"
            / "security-gates"
            / "trusted-manifest.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    public_key_b64 = (
        root
        / "policies"
        / "security-gates"
        / "trusted-manifest-public-key.b64"
    ).read_text(
        encoding="utf-8"
    ).strip()

    public_key = public_key_from_base64(
        public_key_b64
    )

    result = verify_policy_manifest_signature(
        manifest,
        public_key,
    )

    assert result["valid"] is True
    assert result["status"] == "verified"
