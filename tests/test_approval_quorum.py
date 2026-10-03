import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from modules.approval_quorum import (
    ApprovalQuorumError,
    verify_rotation_approval_quorum,
)

from modules.approver_trust_registry import (
    create_approver_registry,
    register_approver,
    revoke_approver_key,
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


def sample_plan():
    return {
        "rotation_version": "1.0",
        "rotation_id": (
            "ROTATION-QUORUM-001"
        ),
        "status": "planned",
        "requires_approval": True,
        "initiated_by": (
            "security-operator"
        ),
        "rotated_at": (
            "2026-10-03T13:00:00+00:00"
        ),
    }


def build_registry():
    keys = {
        "security-admin": (
            Ed25519PrivateKey.generate()
        ),
        "platform-owner": (
            Ed25519PrivateKey.generate()
        ),
        "risk-owner": (
            Ed25519PrivateKey.generate()
        ),
    }

    registry = (
        create_approver_registry(
            created_at=CREATED_AT,
            registry_id=(
                "QUORUM-REGISTRY-001"
            ),
        )
    )

    for index, (
        approver_id,
        key,
    ) in enumerate(
        keys.items(),
        start=1,
    ):
        registry = register_approver(
            registry,
            approver_id=approver_id,
            key_id=(
                f"approver-key-{index:03d}"
            ),
            public_key_b64=(
                public_key_to_base64(
                    key.public_key()
                )
            ),
            registered_at=REGISTERED_AT,
        )

    return registry, keys


def make_approval(
    plan,
    key,
    approver_id,
):
    return sign_rotation_approval(
        plan,
        key,
        initiated_by=(
            plan["initiated_by"]
        ),
        approved_by=approver_id,
        approved_at=APPROVED_AT,
    )


def test_two_unique_approvals_satisfy_quorum():
    registry, keys = build_registry()

    plan = sample_plan()

    approvals = [
        make_approval(
            plan,
            keys["security-admin"],
            "security-admin",
        ),
        make_approval(
            plan,
            keys["platform-owner"],
            "platform-owner",
        ),
    ]

    result = (
        verify_rotation_approval_quorum(
            plan,
            approvals,
            registry,
            required_approvals=2,
        )
    )

    assert result["valid"] is True

    assert (
        result["status"]
        == "quorum_satisfied"
    )

    assert (
        result["valid_approval_count"]
        == 2
    )


def test_one_approval_does_not_satisfy_two_person_quorum():
    registry, keys = build_registry()

    plan = sample_plan()

    approvals = [
        make_approval(
            plan,
            keys["security-admin"],
            "security-admin",
        )
    ]

    result = (
        verify_rotation_approval_quorum(
            plan,
            approvals,
            registry,
            required_approvals=2,
        )
    )

    assert result["valid"] is False

    assert (
        result["status"]
        == "quorum_not_satisfied"
    )

    assert (
        result["valid_approval_count"]
        == 1
    )


def test_duplicate_approver_counts_once():
    registry, keys = build_registry()

    plan = sample_plan()

    approvals = [
        make_approval(
            plan,
            keys["security-admin"],
            "security-admin",
        ),
        make_approval(
            plan,
            keys["security-admin"],
            "security-admin",
        ),
    ]

    result = (
        verify_rotation_approval_quorum(
            plan,
            approvals,
            registry,
            required_approvals=2,
        )
    )

    assert result["valid"] is False

    assert (
        result["valid_approval_count"]
        == 1
    )

    assert any(
        item.get("status")
        == "duplicate_approver"
        for item in (
            result[
                "rejected_approvals"
            ]
        )
    )


def test_three_approvals_satisfy_two_person_quorum():
    registry, keys = build_registry()

    plan = sample_plan()

    approvals = [
        make_approval(
            plan,
            keys["security-admin"],
            "security-admin",
        ),
        make_approval(
            plan,
            keys["platform-owner"],
            "platform-owner",
        ),
        make_approval(
            plan,
            keys["risk-owner"],
            "risk-owner",
        ),
    ]

    result = (
        verify_rotation_approval_quorum(
            plan,
            approvals,
            registry,
            required_approvals=2,
        )
    )

    assert result["valid"] is True

    assert (
        result["valid_approval_count"]
        == 3
    )


def test_invalid_signature_does_not_count():
    registry, keys = build_registry()

    plan = sample_plan()

    approval_a = make_approval(
        plan,
        keys["security-admin"],
        "security-admin",
    )

    approval_b = make_approval(
        plan,
        keys["platform-owner"],
        "platform-owner",
    )

    approval_b["approved_by"] = (
        "risk-owner"
    )

    result = (
        verify_rotation_approval_quorum(
            plan,
            [
                approval_a,
                approval_b,
            ],
            registry,
            required_approvals=2,
        )
    )

    assert result["valid"] is False

    assert (
        result["valid_approval_count"]
        == 1
    )


def test_revoked_approver_after_approval_keeps_historical_vote():
    registry, keys = build_registry()

    plan = sample_plan()

    approval_a = make_approval(
        plan,
        keys["security-admin"],
        "security-admin",
    )

    approval_b = make_approval(
        plan,
        keys["platform-owner"],
        "platform-owner",
    )

    registry = revoke_approver_key(
        registry,
        public_key_fingerprint(
            keys[
                "platform-owner"
            ].public_key()
        ),
        revoked_at=(
            "2026-10-03T12:00:00+00:00"
        ),
        reason="rotation",
    )

    result = (
        verify_rotation_approval_quorum(
            plan,
            [
                approval_a,
                approval_b,
            ],
            registry,
            required_approvals=2,
        )
    )

    assert result["valid"] is True

    assert any(
        item.get(
            "trust_basis"
        )
        == "historical_trust"
        for item in (
            result[
                "accepted_approvals"
            ]
        )
    )


def test_untrusted_approver_does_not_count():
    registry, keys = build_registry()

    plan = sample_plan()

    unknown_key = (
        Ed25519PrivateKey.generate()
    )

    approvals = [
        make_approval(
            plan,
            keys["security-admin"],
            "security-admin",
        ),
        make_approval(
            plan,
            unknown_key,
            "unknown-admin",
        ),
    ]

    result = (
        verify_rotation_approval_quorum(
            plan,
            approvals,
            registry,
            required_approvals=2,
        )
    )

    assert result["valid"] is False

    assert (
        result["valid_approval_count"]
        == 1
    )


def test_approval_for_different_plan_does_not_count():
    registry, keys = build_registry()

    plan = sample_plan()

    other_plan = sample_plan()

    other_plan["rotation_id"] = (
        "ROTATION-OTHER-001"
    )

    approvals = [
        make_approval(
            plan,
            keys["security-admin"],
            "security-admin",
        ),
        make_approval(
            other_plan,
            keys["platform-owner"],
            "platform-owner",
        ),
    ]

    result = (
        verify_rotation_approval_quorum(
            plan,
            approvals,
            registry,
            required_approvals=2,
        )
    )

    assert result["valid"] is False

    assert (
        result["valid_approval_count"]
        == 1
    )


def test_required_quorum_must_be_positive_integer():
    registry, _ = build_registry()

    with pytest.raises(
        ApprovalQuorumError
    ):
        verify_rotation_approval_quorum(
            sample_plan(),
            [],
            registry,
            required_approvals=0,
        )


def test_approvals_must_be_list():
    registry, _ = build_registry()

    with pytest.raises(
        ApprovalQuorumError
    ):
        verify_rotation_approval_quorum(
            sample_plan(),
            {},
            registry,
            required_approvals=2,
        )
