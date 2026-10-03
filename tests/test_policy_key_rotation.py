from copy import deepcopy

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from modules.policy_key_rotation import (
    PolicyKeyRotationError,
    execute_policy_key_rotation,
    plan_policy_key_rotation,
)

from modules.policy_manifest_signing import (
    public_key_fingerprint,
    public_key_to_base64,
    sign_policy_manifest,
)

from modules.policy_signer_registry import (
    create_policy_signer_registry,
    get_policy_signer,
    register_policy_signer,
    revoke_policy_signer,
)


OLD_REGISTERED_AT = (
    "2026-10-03T10:00:00+00:00"
)

MANIFEST_CREATED_AT = (
    "2026-10-03T11:00:00+00:00"
)

ROTATED_AT = (
    "2026-10-03T12:00:00+00:00"
)


def key_material():
    private_key = (
        Ed25519PrivateKey.generate()
    )

    public_key = (
        private_key.public_key()
    )

    return {
        "private": private_key,
        "public_b64": (
            public_key_to_base64(
                public_key
            )
        ),
        "fingerprint": (
            public_key_fingerprint(
                public_key
            )
        ),
    }


def trusted_state():
    old_key = key_material()

    registry = (
        create_policy_signer_registry(
            registry_id="ROTATION-REGISTRY-001",
            created_at=(
                "2026-10-03T09:00:00+00:00"
            ),
        )
    )

    registry = register_policy_signer(
        registry,
        signer_id="policy-authority",
        key_id="policy-key-001",
        public_key_b64=(
            old_key["public_b64"]
        ),
        registered_at=OLD_REGISTERED_AT,
    )

    manifest = {
        "manifest_version": "1.0",
        "manifest_id": "MANIFEST-001",
        "created_at": (
            MANIFEST_CREATED_AT
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

    manifest = sign_policy_manifest(
        manifest,
        old_key["private"],
        signer_id="policy-authority",
        key_id="policy-key-001",
    )

    return (
        old_key,
        registry,
        manifest,
    )


def build_plan(
    old_key,
    registry,
    manifest,
    new_key,
):
    return plan_policy_key_rotation(
        manifest,
        registry,
        old_fingerprint=(
            old_key["fingerprint"]
        ),
        new_private_key=(
            new_key["private"]
        ),
        new_signer_id=(
            "policy-authority"
        ),
        new_key_id="policy-key-002",
        rotated_at=ROTATED_AT,
        rotation_id="ROTATION-001",
        new_manifest_id="MANIFEST-002",
    )


def test_rotation_plan_is_created():
    old_key, registry, manifest = (
        trusted_state()
    )

    new_key = key_material()

    plan = build_plan(
        old_key,
        registry,
        manifest,
        new_key,
    )

    assert plan["status"] == "planned"

    assert (
        plan["requires_approval"]
        is True
    )

    assert (
        plan["old_signer"][
            "key_fingerprint"
        ]
        == old_key["fingerprint"]
    )

    assert (
        plan["new_signer"][
            "key_fingerprint"
        ]
        == new_key["fingerprint"]
    )


def test_plan_rejects_wrong_old_signer():
    old_key, registry, manifest = (
        trusted_state()
    )

    new_key = key_material()

    with pytest.raises(
        PolicyKeyRotationError
    ):
        plan_policy_key_rotation(
            manifest,
            registry,
            old_fingerprint="f" * 64,
            new_private_key=(
                new_key["private"]
            ),
            new_signer_id=(
                "policy-authority"
            ),
            new_key_id="policy-key-002",
            rotated_at=ROTATED_AT,
        )


def test_plan_rejects_revoked_current_signer():
    old_key, registry, manifest = (
        trusted_state()
    )

    registry = revoke_policy_signer(
        registry,
        old_key["fingerprint"],
        revoked_at=(
            "2026-10-03T11:30:00+00:00"
        ),
        reason="test",
    )

    with pytest.raises(
        PolicyKeyRotationError
    ):
        build_plan(
            old_key,
            registry,
            manifest,
            key_material(),
        )


def test_execution_requires_human_approval():
    old_key, registry, manifest = (
        trusted_state()
    )

    new_key = key_material()

    plan = build_plan(
        old_key,
        registry,
        manifest,
        new_key,
    )

    with pytest.raises(
        PolicyKeyRotationError
    ):
        execute_policy_key_rotation(
            plan,
            manifest,
            registry,
            new_key["private"],
            approved_by="",
        )


def test_rotation_revokes_old_and_activates_new():
    old_key, registry, manifest = (
        trusted_state()
    )

    new_key = key_material()

    plan = build_plan(
        old_key,
        registry,
        manifest,
        new_key,
    )

    result = execute_policy_key_rotation(
        plan,
        manifest,
        registry,
        new_key["private"],
        approved_by="security-admin",
    )

    old_signer = get_policy_signer(
        result["registry"],
        old_key["fingerprint"],
    )

    new_signer = get_policy_signer(
        result["registry"],
        new_key["fingerprint"],
    )

    assert old_signer["status"] == "revoked"
    assert new_signer["status"] == "active"


def test_rotated_manifest_uses_new_signer():
    old_key, registry, manifest = (
        trusted_state()
    )

    new_key = key_material()

    plan = build_plan(
        old_key,
        registry,
        manifest,
        new_key,
    )

    result = execute_policy_key_rotation(
        plan,
        manifest,
        registry,
        new_key["private"],
        approved_by="security-admin",
    )

    rotated_manifest = (
        result["manifest"]
    )

    assert (
        rotated_manifest["manifest_id"]
        == "MANIFEST-002"
    )

    assert (
        rotated_manifest["created_at"]
        == ROTATED_AT
    )

    assert (
        rotated_manifest["signature"][
            "key_id"
        ]
        == "policy-key-002"
    )

    assert (
        rotated_manifest["signature"][
            "key_fingerprint"
        ]
        == new_key["fingerprint"]
    )


def test_rotated_manifest_is_currently_trusted():
    old_key, registry, manifest = (
        trusted_state()
    )

    new_key = key_material()

    plan = build_plan(
        old_key,
        registry,
        manifest,
        new_key,
    )

    result = execute_policy_key_rotation(
        plan,
        manifest,
        registry,
        new_key["private"],
        approved_by="security-admin",
    )

    trust = result["verification"]

    assert (
        trust["current_trust"][
            "accepted"
        ]
        is True
    )

    assert (
        trust["effective_trust"][
            "basis"
        ]
        == "current_trust"
    )


def test_execution_rejects_unapproved_new_key():
    old_key, registry, manifest = (
        trusted_state()
    )

    approved_key = key_material()
    different_key = key_material()

    plan = build_plan(
        old_key,
        registry,
        manifest,
        approved_key,
    )

    with pytest.raises(
        PolicyKeyRotationError
    ):
        execute_policy_key_rotation(
            plan,
            manifest,
            registry,
            different_key["private"],
            approved_by="security-admin",
        )


def test_rotation_produces_audit_evidence():
    old_key, registry, manifest = (
        trusted_state()
    )

    new_key = key_material()

    plan = build_plan(
        old_key,
        registry,
        manifest,
        new_key,
    )

    result = execute_policy_key_rotation(
        plan,
        manifest,
        registry,
        new_key["private"],
        approved_by="security-admin",
    )

    audit = result["audit_event"]

    assert (
        audit["action"]
        == "controlled_policy_key_rotation"
    )

    assert (
        audit["approved_by"]
        == "security-admin"
    )

    assert (
        audit["old_key_fingerprint"]
        == old_key["fingerprint"]
    )

    assert (
        audit["new_key_fingerprint"]
        == new_key["fingerprint"]
    )


def test_rotation_does_not_mutate_inputs():
    old_key, registry, manifest = (
        trusted_state()
    )

    new_key = key_material()

    plan = build_plan(
        old_key,
        registry,
        manifest,
        new_key,
    )

    original_registry = deepcopy(
        registry
    )

    original_manifest = deepcopy(
        manifest
    )

    original_plan = deepcopy(
        plan
    )

    execute_policy_key_rotation(
        plan,
        manifest,
        registry,
        new_key["private"],
        approved_by="security-admin",
    )

    assert registry == original_registry
    assert manifest == original_manifest
    assert plan == original_plan
