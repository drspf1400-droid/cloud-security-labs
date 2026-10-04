from copy import deepcopy

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from modules.rotation_approval import (
    RotationApprovalError,
    canonical_plan_bytes,
    rotation_plan_fingerprint,
    sign_rotation_approval,
    verify_rotation_approval,
)


def sample_plan():
    return {
        "rotation_version": "1.0",
        "rotation_id": "ROTATION-APPROVAL-001",
        "status": "planned",
        "requires_approval": True,
        "initiated_by": "security-operator",
        "rotated_at": (
            "2026-10-04T10:00:00+00:00"
        ),
        "source_manifest_id": (
            "MANIFEST-001"
        ),
        "new_manifest_id": (
            "MANIFEST-002"
        ),
        "old_signer": {
            "signer_id": "authority",
            "key_id": "key-001",
            "key_fingerprint": "a" * 64,
        },
        "new_signer": {
            "signer_id": "authority",
            "key_id": "key-002",
            "key_fingerprint": "b" * 64,
            "public_key_b64": "example",
        },
    }


def signed_approval():
    key = Ed25519PrivateKey.generate()

    approval = sign_rotation_approval(
        sample_plan(),
        key,
        initiated_by="security-operator",
        approved_by="security-admin",
        approved_at=(
            "2026-10-04T09:30:00+00:00"
        ),
        approval_id="APPROVAL-001",
    )

    return key, approval


def test_plan_fingerprint_is_stable():
    plan = sample_plan()

    assert (
        rotation_plan_fingerprint(plan)
        == rotation_plan_fingerprint(
            deepcopy(plan)
        )
    )


def test_plan_key_order_does_not_change_hash():
    plan = sample_plan()

    reordered = {
        key: plan[key]
        for key in reversed(
            list(plan.keys())
        )
    }

    assert (
        canonical_plan_bytes(plan)
        == canonical_plan_bytes(
            reordered
        )
    )


def test_signed_approval_verifies():
    key, approval = signed_approval()

    result = verify_rotation_approval(
        sample_plan(),
        approval,
        trusted_public_key=(
            key.public_key()
        ),
    )

    assert result["valid"] is True
    assert result["status"] == "verified"

    assert (
        result["approved_by"]
        == "security-admin"
    )


def test_same_initiator_and_approver_is_rejected():
    key = Ed25519PrivateKey.generate()

    with pytest.raises(
        RotationApprovalError
    ):
        sign_rotation_approval(
            sample_plan(),
            key,
            initiated_by="same-person",
            approved_by="same-person",
            approved_at=(
                "2026-10-04T09:30:00+00:00"
            ),
        )


def test_modified_plan_invalidates_approval():
    key, approval = signed_approval()

    plan = sample_plan()

    plan["new_signer"][
        "key_id"
    ] = "attacker-key"

    result = verify_rotation_approval(
        plan,
        approval,
        trusted_public_key=(
            key.public_key()
        ),
    )

    assert result["valid"] is False
    assert result["status"] == "plan_mismatch"


def test_modified_approval_invalidates_signature():
    key, approval = signed_approval()

    approval["approved_by"] = (
        "different-admin"
    )

    result = verify_rotation_approval(
        sample_plan(),
        approval,
        trusted_public_key=(
            key.public_key()
        ),
    )

    assert result["valid"] is False

    assert result["status"] == (
        "invalid_signature"
    )


def test_wrong_trusted_approver_key_is_rejected():
    _, approval = signed_approval()

    wrong_key = (
        Ed25519PrivateKey
        .generate()
        .public_key()
    )

    result = verify_rotation_approval(
        sample_plan(),
        approval,
        trusted_public_key=wrong_key,
    )

    assert result["valid"] is False

    assert result["status"] == (
        "untrusted_approver_key"
    )


def test_approval_contains_no_private_key():
    _, approval = signed_approval()

    serialized = str(
        approval
    ).lower()

    assert "private_key" not in serialized
    assert "private key" not in serialized


def test_signing_does_not_mutate_plan():
    key = Ed25519PrivateKey.generate()

    plan = sample_plan()
    original = deepcopy(plan)

    sign_rotation_approval(
        plan,
        key,
        initiated_by="security-operator",
        approved_by="security-admin",
        approved_at=(
            "2026-10-04T09:30:00+00:00"
        ),
    )

    assert plan == original


def test_approval_initiator_must_match_plan():
    key = Ed25519PrivateKey.generate()

    with pytest.raises(
        RotationApprovalError,
        match="does not match",
    ):
        sign_rotation_approval(
            sample_plan(),
            key,
            initiated_by="different-operator",
            approved_by="security-admin",
            approved_at=(
                "2026-10-04T09:30:00+00:00"
            ),
        )


def test_execute_scoped_approval_verifies():
    key = Ed25519PrivateKey.generate()

    approval = sign_rotation_approval(
        sample_plan(),
        key,
        initiated_by="security-operator",
        approved_by="security-admin",
        approved_at=(
            "2026-10-04T09:30:00+00:00"
        ),
        approval_scope="execute",
    )

    result = verify_rotation_approval(
        sample_plan(),
        approval,
        trusted_public_key=(
            key.public_key()
        ),
        required_scope="execute",
    )

    assert result["valid"] is True

    assert (
        result["approval_scope"]
        == "execute"
    )


def test_wrong_approval_scope_is_rejected():
    key = Ed25519PrivateKey.generate()

    approval = sign_rotation_approval(
        sample_plan(),
        key,
        initiated_by="security-operator",
        approved_by="security-admin",
        approved_at=(
            "2026-10-04T09:30:00+00:00"
        ),
        approval_scope="promote",
    )

    result = verify_rotation_approval(
        sample_plan(),
        approval,
        trusted_public_key=(
            key.public_key()
        ),
        required_scope="execute",
    )

    assert result["valid"] is False

    assert (
        result["status"]
        == "approval_scope_mismatch"
    )


def test_invalid_approval_scope_is_rejected_at_signing():
    key = Ed25519PrivateKey.generate()

    with pytest.raises(
        RotationApprovalError
    ):
        sign_rotation_approval(
            sample_plan(),
            key,
            initiated_by="security-operator",
            approved_by="security-admin",
            approved_at=(
                "2026-10-04T09:30:00+00:00"
            ),
            approval_scope="delete-everything",
        )
