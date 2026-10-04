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
            roles=[
                approver_id
            ],
        )

    return registry, keys


def make_approval(
    plan,
    key,
    approver_id,
    approval_scope="rotation",
):
    return sign_rotation_approval(
        plan,
        key,
        initiated_by=(
            plan["initiated_by"]
        ),
        approved_by=approver_id,
        approved_at=APPROVED_AT,
        approval_scope=(
            approval_scope
        ),
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


def test_required_roles_are_satisfied():
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
            required_roles=[
                "security-admin",
                "platform-owner",
            ],
        )
    )

    assert result["valid"] is True

    assert result["missing_roles"] == []

    assert set(
        result["satisfied_roles"]
    ) >= {
        "security-admin",
        "platform-owner",
    }


def test_required_role_missing_rejects_quorum():
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
            required_roles=[
                "security-admin",
                "platform-owner",
            ],
        )
    )

    assert result["valid"] is False

    assert (
        result["status"]
        == "required_roles_not_satisfied"
    )

    assert result["missing_roles"] == [
        "platform-owner"
    ]


def test_required_roles_do_not_replace_approval_count():
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
            required_roles=[
                "security-admin",
            ],
        )
    )

    assert result["valid"] is False

    assert (
        result["status"]
        == "quorum_not_satisfied"
    )


def test_required_roles_must_be_list():
    registry, _ = build_registry()

    with pytest.raises(
        ApprovalQuorumError
    ):
        verify_rotation_approval_quorum(
            sample_plan(),
            [],
            registry,
            required_approvals=1,
            required_roles="security-admin",
        )


def test_duplicate_required_roles_are_rejected():
    registry, _ = build_registry()

    with pytest.raises(
        ApprovalQuorumError
    ):
        verify_rotation_approval_quorum(
            sample_plan(),
            [],
            registry,
            required_approvals=1,
            required_roles=[
                "security-admin",
                "security-admin",
            ],
        )


def test_distinct_role_holders_are_satisfied():
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
            required_roles=[
                "security-admin",
                "platform-owner",
            ],
            require_distinct_role_holders=True,
        )
    )

    assert result["valid"] is True

    assert (
        result[
            "distinct_role_holders_satisfied"
        ]
        is True
    )

    assert result["role_assignments"] == {
        "security-admin": "security-admin",
        "platform-owner": "platform-owner",
    }


def test_one_multi_role_approver_cannot_cover_two_required_roles():
    registry, keys = build_registry()

    for entry in registry["approvers"]:
        if (
            entry["approver_id"]
            == "security-admin"
        ):
            entry["roles"] = [
                "security-admin",
                "platform-owner",
            ]

    plan = sample_plan()

    approvals = [
        make_approval(
            plan,
            keys["security-admin"],
            "security-admin",
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
            required_roles=[
                "security-admin",
                "platform-owner",
            ],
            require_distinct_role_holders=True,
        )
    )

    assert result["valid"] is False

    assert result["missing_roles"] == []

    assert (
        result["status"]
        == "distinct_role_holders_not_satisfied"
    )

    assert (
        result[
            "distinct_role_holders_satisfied"
        ]
        is False
    )

    assert len(
        result[
            "distinct_role_unassigned_roles"
        ]
    ) == 1


def test_distinct_role_holder_flag_must_be_boolean():
    registry, _ = build_registry()

    with pytest.raises(
        ApprovalQuorumError
    ):
        verify_rotation_approval_quorum(
            sample_plan(),
            [],
            registry,
            required_approvals=1,
            required_roles=[],
            require_distinct_role_holders="yes",
        )


def test_fresh_approval_satisfies_freshness_policy():
    registry, keys = build_registry()

    plan = sample_plan()

    approval = make_approval(
        plan,
        keys["security-admin"],
        "security-admin",
    )

    result = (
        verify_rotation_approval_quorum(
            plan,
            [approval],
            registry,
            required_approvals=1,
            max_approval_age_seconds=3600,
            reference_time=(
                "2026-10-03T11:30:00+00:00"
            ),
        )
    )

    assert result["valid"] is True

    assert (
        result["expired_approval_count"]
        == 0
    )

    assert (
        result["future_approval_count"]
        == 0
    )


def test_expired_approval_is_rejected():
    registry, keys = build_registry()

    plan = sample_plan()

    approval = make_approval(
        plan,
        keys["security-admin"],
        "security-admin",
    )

    result = (
        verify_rotation_approval_quorum(
            plan,
            [approval],
            registry,
            required_approvals=1,
            max_approval_age_seconds=3600,
            reference_time=(
                "2026-10-03T12:30:00+00:00"
            ),
        )
    )

    assert result["valid"] is False

    assert (
        result["status"]
        == "approval_freshness_not_satisfied"
    )

    assert (
        result["expired_approval_count"]
        == 1
    )

    assert (
        result["rejected_approvals"][0][
            "status"
        ]
        == "approval_expired"
    )


def test_future_approval_is_rejected():
    registry, keys = build_registry()

    plan = sample_plan()

    approval = make_approval(
        plan,
        keys["security-admin"],
        "security-admin",
    )

    result = (
        verify_rotation_approval_quorum(
            plan,
            [approval],
            registry,
            required_approvals=1,
            max_approval_age_seconds=3600,
            reference_time=(
                "2026-10-03T10:30:00+00:00"
            ),
        )
    )

    assert result["valid"] is False

    assert (
        result["future_approval_count"]
        == 1
    )

    assert (
        result["rejected_approvals"][0][
            "status"
        ]
        == "approval_from_future"
    )


def test_freshness_requires_reference_time():
    registry, _ = build_registry()

    with pytest.raises(
        ApprovalQuorumError
    ):
        verify_rotation_approval_quorum(
            sample_plan(),
            [],
            registry,
            required_approvals=1,
            max_approval_age_seconds=3600,
        )


def test_max_approval_age_must_be_positive():
    registry, _ = build_registry()

    with pytest.raises(
        ApprovalQuorumError
    ):
        verify_rotation_approval_quorum(
            sample_plan(),
            [],
            registry,
            required_approvals=1,
            max_approval_age_seconds=0,
            reference_time=(
                "2026-10-03T12:00:00+00:00"
            ),
        )


def test_execute_scoped_approvals_satisfy_required_scope():
    registry, keys = build_registry()

    plan = sample_plan()

    approvals = [
        make_approval(
            plan,
            keys["security-admin"],
            "security-admin",
            approval_scope="execute",
        ),
        make_approval(
            plan,
            keys["platform-owner"],
            "platform-owner",
            approval_scope="execute",
        ),
    ]

    result = verify_rotation_approval_quorum(
        plan,
        approvals,
        registry,
        required_approvals=2,
        required_scope="execute",
    )

    assert result["valid"] is True

    assert (
        result["required_scope"]
        == "execute"
    )

    assert (
        result["scope_mismatch_count"]
        == 0
    )


def test_wrong_scope_does_not_count_toward_quorum():
    registry, keys = build_registry()

    plan = sample_plan()

    approval = make_approval(
        plan,
        keys["security-admin"],
        "security-admin",
        approval_scope="promote",
    )

    result = verify_rotation_approval_quorum(
        plan,
        [approval],
        registry,
        required_approvals=1,
        required_scope="execute",
    )

    assert result["valid"] is False

    assert (
        result["status"]
        == "approval_scope_not_satisfied"
    )

    assert (
        result["scope_mismatch_count"]
        == 1
    )

    assert (
        result["rejected_approvals"][0][
            "status"
        ]
        == "approval_scope_mismatch"
    )


def test_required_scope_must_be_supported():
    registry, _ = build_registry()

    with pytest.raises(
        ApprovalQuorumError
    ):
        verify_rotation_approval_quorum(
            sample_plan(),
            [],
            registry,
            required_approvals=1,
            required_scope="unsupported",
        )
