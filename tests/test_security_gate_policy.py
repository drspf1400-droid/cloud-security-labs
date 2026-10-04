import json

import pytest

from modules.security_gate_policy import (
    SecurityGatePolicyError,
    load_security_gate_policy,
    validate_security_gate_policy,
)


def test_lab_policy_loads():
    result = load_security_gate_policy(
        "lab"
    )

    assert (
        result["document"]["environment"]
        == "lab"
    )

    assert (
        result["gate"][
            "max_blocked_executions"
        ]
        == 10
    )


def test_staging_policy_loads():
    result = load_security_gate_policy(
        "staging"
    )

    assert (
        result["gate"][
            "max_critical_findings"
        ]
        == 0
    )

    assert (
        result["gate"][
            "max_blocked_executions"
        ]
        == 2
    )


def test_production_policy_is_strict():
    result = load_security_gate_policy(
        "production"
    )

    gate = result["gate"]

    assert "partial" in (
        gate[
            "fail_on_assurance_states"
        ]
    )

    assert "unknown" in (
        gate[
            "fail_on_trust_decisions"
        ]
    )

    assert (
        gate["max_blocked_executions"]
        == 0
    )


def test_unknown_environment_is_rejected():
    with pytest.raises(
        SecurityGatePolicyError
    ):
        load_security_gate_policy(
            "development"
        )


def test_missing_policy_file_is_rejected(
    tmp_path,
):
    with pytest.raises(
        SecurityGatePolicyError
    ):
        load_security_gate_policy(
            "lab",
            policy_dir=tmp_path,
        )


def test_environment_mismatch_is_rejected(
    tmp_path,
):
    policy = {
        "policy_version": "1.0",
        "policy_name": "bad-policy",
        "environment": "production",
        "gate": {
            "fail_on_assurance_states": [],
            "fail_on_trust_decisions": [],
            "max_critical_findings": 0,
            "max_failed_executions": 0,
            "max_blocked_executions": 0
        },
        "rotation_approval": {
            "required_approvals": 1,
            "required_roles": [],
            "require_distinct_role_holders": False
        }
    }

    path = tmp_path / "lab.json"

    path.write_text(
        json.dumps(policy),
        encoding="utf-8",
    )

    with pytest.raises(
        SecurityGatePolicyError
    ):
        load_security_gate_policy(
            "lab",
            policy_dir=tmp_path,
        )


def test_negative_limit_is_rejected():
    policy = {
        "policy_version": "1.0",
        "policy_name": "invalid-policy",
        "environment": "lab",
        "gate": {
            "fail_on_assurance_states": [],
            "fail_on_trust_decisions": [],
            "max_critical_findings": -1,
            "max_failed_executions": 0,
            "max_blocked_executions": 0
        },
        "rotation_approval": {
            "required_approvals": 1,
            "required_roles": [],
            "require_distinct_role_holders": False
        }
    }

    with pytest.raises(
        SecurityGatePolicyError
    ):
        validate_security_gate_policy(
            policy
        )


def test_policy_loader_returns_independent_copy():
    first = load_security_gate_policy(
        "production"
    )

    second = load_security_gate_policy(
        "production"
    )

    first["gate"][
        "max_blocked_executions"
    ] = 99

    assert (
        second["gate"][
            "max_blocked_executions"
        ]
        == 0
    )


def test_rotation_approval_policy_by_environment():
    lab = load_security_gate_policy(
        "lab"
    )

    staging = load_security_gate_policy(
        "staging"
    )

    production = load_security_gate_policy(
        "production"
    )

    assert (
        lab["rotation_approval"][
            "required_approvals"
        ]
        == 1
    )

    assert (
        staging["rotation_approval"][
            "required_approvals"
        ]
        == 1
    )

    assert (
        production["rotation_approval"][
            "required_approvals"
        ]
        == 2
    )


def test_invalid_rotation_approval_quorum_is_rejected():
    policy = {
        "policy_version": "1.0",
        "policy_name": "invalid-quorum",
        "environment": "production",
        "gate": {
            "fail_on_assurance_states": [],
            "fail_on_trust_decisions": [],
            "max_critical_findings": 0,
            "max_failed_executions": 0,
            "max_blocked_executions": 0
        },
        "rotation_approval": {
            "required_approvals": 0,
            "required_roles": [],
            "require_distinct_role_holders": False
        }
    }

    with pytest.raises(
        SecurityGatePolicyError
    ):
        validate_security_gate_policy(
            policy
        )


def test_production_requires_distinct_security_roles():
    policy = load_security_gate_policy(
        "production"
    )

    assert (
        policy["rotation_approval"][
            "required_approvals"
        ]
        == 2
    )

    assert (
        policy["rotation_approval"][
            "required_roles"
        ]
        == [
            "security-admin",
            "platform-owner",
        ]
    )


def test_duplicate_required_policy_roles_are_rejected():
    policy = {
        "policy_version": "1.0",
        "policy_name": "bad-role-policy",
        "environment": "production",
        "gate": {
            "fail_on_assurance_states": [],
            "fail_on_trust_decisions": [],
            "max_critical_findings": 0,
            "max_failed_executions": 0,
            "max_blocked_executions": 0
        },
        "rotation_approval": {
            "required_approvals": 2,
            "required_roles": [
                "security-admin",
                "security-admin"
            ],
            "require_distinct_role_holders": True
        }
    }

    with pytest.raises(
        SecurityGatePolicyError
    ):
        validate_security_gate_policy(
            policy
        )


def test_distinct_role_holder_policy_by_environment():
    lab = load_security_gate_policy("lab")
    staging = load_security_gate_policy("staging")
    production = load_security_gate_policy(
        "production"
    )

    assert (
        lab["rotation_approval"][
            "require_distinct_role_holders"
        ]
        is False
    )

    assert (
        staging["rotation_approval"][
            "require_distinct_role_holders"
        ]
        is False
    )

    assert (
        production["rotation_approval"][
            "require_distinct_role_holders"
        ]
        is True
    )


def test_distinct_role_holder_policy_must_be_boolean():
    policy = {
        "policy_version": "1.0",
        "policy_name": "invalid-distinct-role",
        "environment": "production",
        "gate": {
            "fail_on_assurance_states": [],
            "fail_on_trust_decisions": [],
            "max_critical_findings": 0,
            "max_failed_executions": 0,
            "max_blocked_executions": 0
        },
        "rotation_approval": {
            "required_approvals": 2,
            "required_roles": [
                "security-admin",
                "platform-owner"
            ],
            "require_distinct_role_holders": "yes"
        }
    }

    with pytest.raises(
        SecurityGatePolicyError
    ):
        validate_security_gate_policy(
            policy
        )
