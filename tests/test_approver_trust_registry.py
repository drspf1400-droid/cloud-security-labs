from copy import deepcopy

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from modules.approver_trust_registry import (
    ApproverTrustRegistryError,
    approver_registry_fingerprint,
    create_approver_registry,
    evaluate_approver_trust,
    register_approver,
    revoke_approver_key,
    verify_rotation_approval_with_registry,
)

from modules.policy_manifest_signing import (
    public_key_fingerprint,
    public_key_to_base64,
)

from modules.rotation_approval import (
    sign_rotation_approval,
)


CREATED_AT = (
    "2026-10-03T10:00:00+00:00"
)

REGISTERED_AT = (
    "2026-10-03T10:30:00+00:00"
)

APPROVED_AT = (
    "2026-10-03T11:00:00+00:00"
)

REVOKED_AT = (
    "2026-10-03T12:00:00+00:00"
)


def sample_plan():
    return {
        "rotation_version": "1.0",
        "rotation_id": "ROTATION-REGISTRY-001",
        "status": "planned",
        "requires_approval": True,
        "initiated_by": "security-operator",
        "rotated_at": (
            "2026-10-03T13:00:00+00:00"
        ),
    }


def build_registry():
    key = Ed25519PrivateKey.generate()

    registry = create_approver_registry(
        created_at=CREATED_AT,
        registry_id=(
            "APPROVER-REGISTRY-TEST-001"
        ),
    )

    registry = register_approver(
        registry,
        approver_id="security-admin",
        key_id="approver-key-001",
        public_key_b64=(
            public_key_to_base64(
                key.public_key()
            )
        ),
        registered_at=REGISTERED_AT,
    )

    return registry, key


def test_empty_registry_is_created():
    registry = create_approver_registry(
        created_at=CREATED_AT,
        registry_id="REGISTRY-001",
    )

    assert (
        registry["registry_version"]
        == "1.0"
    )

    assert registry["approvers"] == []


def test_register_approver_key():
    registry, key = build_registry()

    entry = registry[
        "approvers"
    ][0]

    assert entry["status"] == "active"

    assert (
        entry["approver_id"]
        == "security-admin"
    )

    assert (
        entry["key_fingerprint"]
        == public_key_fingerprint(
            key.public_key()
        )
    )


def test_registration_does_not_mutate_input():
    registry = create_approver_registry(
        created_at=CREATED_AT,
    )

    original = deepcopy(
        registry
    )

    key = Ed25519PrivateKey.generate()

    register_approver(
        registry,
        approver_id="security-admin",
        key_id="key-001",
        public_key_b64=(
            public_key_to_base64(
                key.public_key()
            )
        ),
        registered_at=REGISTERED_AT,
    )

    assert registry == original


def test_duplicate_key_is_rejected():
    registry, key = build_registry()

    with pytest.raises(
        ApproverTrustRegistryError
    ):
        register_approver(
            registry,
            approver_id="another-admin",
            key_id="key-002",
            public_key_b64=(
                public_key_to_base64(
                    key.public_key()
                )
            ),
            registered_at=(
                "2026-10-03T11:00:00+00:00"
            ),
        )


def test_revoke_approver_key():
    registry, key = build_registry()

    revoked = revoke_approver_key(
        registry,
        public_key_fingerprint(
            key.public_key()
        ),
        revoked_at=REVOKED_AT,
        reason="rotation",
    )

    entry = revoked[
        "approvers"
    ][0]

    assert entry["status"] == "revoked"
    assert entry["revoked_at"] == REVOKED_AT


def test_active_key_is_trusted():
    registry, key = build_registry()

    trust = evaluate_approver_trust(
        registry,
        approver_id="security-admin",
        key_fingerprint=(
            public_key_fingerprint(
                key.public_key()
            )
        ),
        at_time=APPROVED_AT,
    )

    assert trust["accepted"] is True
    assert trust["basis"] == "active_trust"


def test_revoked_key_retains_historical_trust():
    registry, key = build_registry()

    registry = revoke_approver_key(
        registry,
        public_key_fingerprint(
            key.public_key()
        ),
        revoked_at=REVOKED_AT,
    )

    trust = evaluate_approver_trust(
        registry,
        approver_id="security-admin",
        key_fingerprint=(
            public_key_fingerprint(
                key.public_key()
            )
        ),
        at_time=APPROVED_AT,
    )

    assert trust["accepted"] is True

    assert (
        trust["basis"]
        == "historical_trust"
    )


def test_approval_after_revocation_is_rejected():
    registry, key = build_registry()

    registry = revoke_approver_key(
        registry,
        public_key_fingerprint(
            key.public_key()
        ),
        revoked_at=REVOKED_AT,
    )

    trust = evaluate_approver_trust(
        registry,
        approver_id="security-admin",
        key_fingerprint=(
            public_key_fingerprint(
                key.public_key()
            )
        ),
        at_time=(
            "2026-10-03T12:30:00+00:00"
        ),
    )

    assert trust["accepted"] is False

    assert (
        trust["basis"]
        == "revoked_at_approval_time"
    )


def test_key_before_registration_is_rejected():
    registry, key = build_registry()

    trust = evaluate_approver_trust(
        registry,
        approver_id="security-admin",
        key_fingerprint=(
            public_key_fingerprint(
                key.public_key()
            )
        ),
        at_time=(
            "2026-10-03T10:15:00+00:00"
        ),
    )

    assert trust["accepted"] is False

    assert (
        trust["basis"]
        == "key_not_yet_trusted"
    )


def test_signed_approval_verifies_with_registry():
    registry, key = build_registry()

    plan = sample_plan()

    approval = sign_rotation_approval(
        plan,
        key,
        initiated_by=(
            "security-operator"
        ),
        approved_by="security-admin",
        approved_at=APPROVED_AT,
        approval_id=(
            "APPROVAL-REGISTRY-001"
        ),
    )

    result = (
        verify_rotation_approval_with_registry(
            plan,
            approval,
            registry,
        )
    )

    assert result["valid"] is True

    assert (
        result["trust_basis"]
        == "active_trust"
    )

    assert (
        result["approver_key_id"]
        == "approver-key-001"
    )


def test_wrong_approver_identity_is_rejected():
    registry, key = build_registry()

    plan = sample_plan()

    approval = sign_rotation_approval(
        plan,
        key,
        initiated_by=(
            "security-operator"
        ),
        approved_by="different-admin",
        approved_at=APPROVED_AT,
    )

    result = (
        verify_rotation_approval_with_registry(
            plan,
            approval,
            registry,
        )
    )

    assert result["valid"] is False

    assert (
        result["status"]
        == "untrusted_approver"
    )


def test_registry_fingerprint_is_stable():
    registry, _ = build_registry()

    clone = deepcopy(
        registry
    )

    assert (
        approver_registry_fingerprint(
            registry
        )
        == approver_registry_fingerprint(
            clone
        )
    )


def test_registered_approver_roles_are_returned():
    key = Ed25519PrivateKey.generate()

    registry = create_approver_registry(
        created_at=CREATED_AT,
    )

    registry = register_approver(
        registry,
        approver_id="security-admin",
        key_id="role-key-001",
        public_key_b64=(
            public_key_to_base64(
                key.public_key()
            )
        ),
        registered_at=REGISTERED_AT,
        roles=[
            "security-admin",
            "incident-approver",
        ],
    )

    plan = sample_plan()

    approval = sign_rotation_approval(
        plan,
        key,
        initiated_by=(
            plan["initiated_by"]
        ),
        approved_by="security-admin",
        approved_at=APPROVED_AT,
    )

    result = (
        verify_rotation_approval_with_registry(
            plan,
            approval,
            registry,
        )
    )

    assert result["valid"] is True

    assert result["approver_roles"] == [
        "security-admin",
        "incident-approver",
    ]
