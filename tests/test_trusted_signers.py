from copy import deepcopy

from modules.evidence_signing import (
    generate_ed25519_keypair,
    public_key_fingerprint,
    sign_execution_manifest,
)

from modules.execution_evidence import (
    build_execution_evidence,
)

from modules.trusted_signers import (
    create_registry,
    register_signer_key,
    revoke_signer_key,
    rotate_signer_key,
    verify_trusted_manifest,
)


def sample_manifest():
    execution_result = {
        "environment": "lab",
        "summary": {
            "executed": 0,
            "dry_run": 0,
            "blocked": 1,
            "failed": 0,
        },
        "results": [
            {
                "finding_id": "UNKNOWN-001",
                "decision": "blocked",
                "action": None,
                "status": "blocked",
                "reason": "Blocked by policy.",
            }
        ],
        "assessment": {
            "findings": [
                {
                    "finding_id": "UNKNOWN-001",
                    "status": "approved",
                    "remediation": {
                        "applied": False,
                    },
                    "audit_trail": [],
                }
            ]
        },
    }

    return build_execution_evidence(
        execution_result,
        actor="tester",
        run_id="RUN-TRUST-001",
        timestamp=(
            "2026-09-29T10:00:00+00:00"
        ),
    )


def test_registered_active_signer_is_accepted():
    private_key, public_key = (
        generate_ed25519_keypair()
    )

    registry = register_signer_key(
        create_registry(),
        signer_id="security-automation",
        key_id="key-2026-01",
        public_key=public_key,
        registered_at=(
            "2026-09-29T10:00:00+00:00"
        ),
    )

    manifest = sign_execution_manifest(
        sample_manifest(),
        private_key,
    )

    result = verify_trusted_manifest(
        manifest,
        registry,
    )

    assert result["accepted"] is True
    assert result["trusted"] is True
    assert result["signature_valid"] is True
    assert result["status"] == "trusted"


def test_unknown_signer_is_rejected():
    private_key, _ = (
        generate_ed25519_keypair()
    )

    manifest = sign_execution_manifest(
        sample_manifest(),
        private_key,
    )

    result = verify_trusted_manifest(
        manifest,
        create_registry(),
    )

    assert result["accepted"] is False
    assert result["status"] == "unknown"


def test_revoked_signer_is_rejected():
    private_key, public_key = (
        generate_ed25519_keypair()
    )

    registry = register_signer_key(
        create_registry(),
        signer_id="security-automation",
        key_id="key-old",
        public_key=public_key,
    )

    fingerprint = public_key_fingerprint(
        public_key
    )

    registry = revoke_signer_key(
        registry,
        fingerprint,
        reason="Compromised key",
        revoked_at=(
            "2026-09-29T11:00:00+00:00"
        ),
    )

    manifest = sign_execution_manifest(
        sample_manifest(),
        private_key,
    )

    result = verify_trusted_manifest(
        manifest,
        registry,
    )

    assert result["accepted"] is False
    assert result["status"] == "revoked"


def test_key_rotation_revokes_old_and_activates_new():
    _, old_public_key = (
        generate_ed25519_keypair()
    )

    _, new_public_key = (
        generate_ed25519_keypair()
    )

    registry = register_signer_key(
        create_registry(),
        signer_id="security-automation",
        key_id="key-old",
        public_key=old_public_key,
    )

    old_fingerprint = (
        public_key_fingerprint(
            old_public_key
        )
    )

    new_fingerprint = (
        public_key_fingerprint(
            new_public_key
        )
    )

    rotated = rotate_signer_key(
        registry,
        signer_id="security-automation",
        old_fingerprint=old_fingerprint,
        new_key_id="key-new",
        new_public_key=new_public_key,
        rotated_at=(
            "2026-09-29T12:00:00+00:00"
        ),
    )

    assert (
        rotated["signers"]
        [old_fingerprint]
        ["status"]
        == "revoked"
    )

    assert (
        rotated["signers"]
        [new_fingerprint]
        ["status"]
        == "active"
    )


def test_old_manifest_is_rejected_after_rotation():
    old_private, old_public = (
        generate_ed25519_keypair()
    )

    new_private, new_public = (
        generate_ed25519_keypair()
    )

    registry = register_signer_key(
        create_registry(),
        signer_id="security-automation",
        key_id="key-old",
        public_key=old_public,
    )

    old_manifest = sign_execution_manifest(
        sample_manifest(),
        old_private,
    )

    old_fingerprint = (
        public_key_fingerprint(
            old_public
        )
    )

    registry = rotate_signer_key(
        registry,
        signer_id="security-automation",
        old_fingerprint=old_fingerprint,
        new_key_id="key-new",
        new_public_key=new_public,
    )

    old_result = verify_trusted_manifest(
        old_manifest,
        registry,
    )

    new_manifest = sign_execution_manifest(
        sample_manifest(),
        new_private,
    )

    new_result = verify_trusted_manifest(
        new_manifest,
        registry,
    )

    assert old_result["accepted"] is False
    assert old_result["status"] == "revoked"

    assert new_result["accepted"] is True
    assert new_result["status"] == "trusted"


def test_tampered_manifest_from_trusted_signer_is_rejected():
    private_key, public_key = (
        generate_ed25519_keypair()
    )

    registry = register_signer_key(
        create_registry(),
        signer_id="security-automation",
        key_id="key-1",
        public_key=public_key,
    )

    manifest = sign_execution_manifest(
        sample_manifest(),
        private_key,
    )

    manifest["summary"]["blocked"] = 999

    result = verify_trusted_manifest(
        manifest,
        registry,
    )

    assert result["accepted"] is False
    assert result["trusted"] is True
    assert result["signature_valid"] is False
    assert result["status"] == "invalid_signature"


def test_registry_operations_do_not_mutate_original():
    _, public_key = (
        generate_ed25519_keypair()
    )

    registry = create_registry()
    original = deepcopy(registry)

    updated = register_signer_key(
        registry,
        signer_id="security-automation",
        key_id="key-1",
        public_key=public_key,
    )

    assert registry == original
    assert updated != registry


def test_duplicate_key_registration_is_rejected():
    import pytest

    _, public_key = (
        generate_ed25519_keypair()
    )

    registry = register_signer_key(
        create_registry(),
        signer_id="security-automation",
        key_id="key-1",
        public_key=public_key,
    )

    with pytest.raises(
        ValueError,
        match="already registered",
    ):
        register_signer_key(
            registry,
            signer_id="security-automation",
            key_id="key-duplicate",
            public_key=public_key,
        )


def test_registration_creates_audit_evidence():
    _, public_key = generate_ed25519_keypair()

    registry = register_signer_key(
        create_registry(),
        signer_id="security-automation",
        key_id="key-1",
        public_key=public_key,
        registered_at="2026-09-29T10:00:00+00:00",
    )

    assert len(registry["audit_trail"]) == 1

    event = registry["audit_trail"][0]

    assert event["action"] == "signer_key_registered"
    assert event["signer_id"] == "security-automation"
    assert event["key_id"] == "key-1"


def test_revocation_creates_audit_evidence():
    _, public_key = generate_ed25519_keypair()

    registry = register_signer_key(
        create_registry(),
        signer_id="security-automation",
        key_id="key-1",
        public_key=public_key,
    )

    fingerprint = public_key_fingerprint(
        public_key
    )

    registry = revoke_signer_key(
        registry,
        fingerprint,
        reason="Compromised key",
        revoked_at="2026-09-29T11:00:00+00:00",
    )

    event = registry["audit_trail"][-1]

    assert event["action"] == "signer_key_revoked"
    assert event["details"]["reason"] == "Compromised key"


def test_rotation_creates_linked_audit_evidence():
    _, old_public = generate_ed25519_keypair()
    _, new_public = generate_ed25519_keypair()

    registry = register_signer_key(
        create_registry(),
        signer_id="security-automation",
        key_id="key-old",
        public_key=old_public,
    )

    old_fingerprint = public_key_fingerprint(
        old_public
    )

    new_fingerprint = public_key_fingerprint(
        new_public
    )

    registry = rotate_signer_key(
        registry,
        signer_id="security-automation",
        old_fingerprint=old_fingerprint,
        new_key_id="key-new",
        new_public_key=new_public,
        rotated_at="2026-09-29T12:00:00+00:00",
    )

    event = registry["audit_trail"][-1]

    assert event["action"] == "signer_key_rotated"

    assert (
        event["details"]["old_fingerprint"]
        == old_fingerprint
    )

    assert (
        event["details"]["new_fingerprint"]
        == new_fingerprint
    )


def test_registry_is_json_serializable_and_schema_valid():
    import json
    from pathlib import Path

    from jsonschema import validate

    _, public_key = generate_ed25519_keypair()

    registry = register_signer_key(
        create_registry(),
        signer_id="security-automation",
        key_id="key-1",
        public_key=public_key,
        registered_at="2026-09-29T10:00:00+00:00",
    )

    serialized = json.dumps(registry)
    restored = json.loads(serialized)

    assert restored == registry

    schema = json.loads(
        Path(
            "schemas/trusted-signer-registry-schema.json"
        ).read_text()
    )

    validate(
        instance=registry,
        schema=schema,
    )
