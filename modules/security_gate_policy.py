#!/usr/bin/env python3

import json
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

DEFAULT_POLICY_DIR = (
    ROOT
    / "policies"
    / "security-gates"
)

SUPPORTED_ENVIRONMENTS = {
    "lab",
    "staging",
    "production",
}

REQUIRED_GATE_FIELDS = {
    "fail_on_assurance_states",
    "fail_on_trust_decisions",
    "max_critical_findings",
    "max_failed_executions",
    "max_blocked_executions",
}


class SecurityGatePolicyError(ValueError):
    pass


def _validate_string_list(
    value,
    field_name,
):
    if not isinstance(value, list):
        raise SecurityGatePolicyError(
            f"{field_name} must be a list"
        )

    if not all(
        isinstance(item, str)
        for item in value
    ):
        raise SecurityGatePolicyError(
            f"{field_name} must contain only strings"
        )


def _validate_limit(
    value,
    field_name,
):
    if value is None:
        return

    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
    ):
        raise SecurityGatePolicyError(
            f"{field_name} must be a "
            "non-negative integer or null"
        )


def validate_security_gate_policy(
    document,
    *,
    expected_environment=None,
):
    if not isinstance(document, dict):
        raise SecurityGatePolicyError(
            "Policy document must be an object"
        )

    if document.get("policy_version") != "1.0":
        raise SecurityGatePolicyError(
            "Unsupported policy_version"
        )

    environment = document.get(
        "environment"
    )

    if environment not in SUPPORTED_ENVIRONMENTS:
        raise SecurityGatePolicyError(
            "Unsupported policy environment: "
            f"{environment}"
        )

    if (
        expected_environment is not None
        and environment != expected_environment
    ):
        raise SecurityGatePolicyError(
            "Policy environment mismatch: "
            f"expected {expected_environment}, "
            f"found {environment}"
        )

    gate = document.get("gate")

    if not isinstance(gate, dict):
        raise SecurityGatePolicyError(
            "Policy gate must be an object"
        )

    missing = (
        REQUIRED_GATE_FIELDS
        - set(gate)
    )

    if missing:
        raise SecurityGatePolicyError(
            "Missing gate policy fields: "
            + ", ".join(sorted(missing))
        )

    _validate_string_list(
        gate["fail_on_assurance_states"],
        "fail_on_assurance_states",
    )

    _validate_string_list(
        gate["fail_on_trust_decisions"],
        "fail_on_trust_decisions",
    )

    _validate_limit(
        gate["max_critical_findings"],
        "max_critical_findings",
    )

    _validate_limit(
        gate["max_failed_executions"],
        "max_failed_executions",
    )

    _validate_limit(
        gate["max_blocked_executions"],
        "max_blocked_executions",
    )

    return True


def load_security_gate_policy(
    environment,
    *,
    policy_dir=None,
):
    if environment not in SUPPORTED_ENVIRONMENTS:
        raise SecurityGatePolicyError(
            "Unsupported environment: "
            f"{environment}"
        )

    base_dir = Path(
        policy_dir
        if policy_dir is not None
        else DEFAULT_POLICY_DIR
    )

    policy_path = (
        base_dir
        / f"{environment}.json"
    )

    if not policy_path.exists():
        raise SecurityGatePolicyError(
            "Security gate policy not found: "
            f"{policy_path}"
        )

    try:
        document = json.loads(
            policy_path.read_text(
                encoding="utf-8"
            )
        )
    except json.JSONDecodeError as exc:
        raise SecurityGatePolicyError(
            "Invalid security gate policy JSON: "
            f"{policy_path}: {exc}"
        ) from exc

    validate_security_gate_policy(
        document,
        expected_environment=environment,
    )

    return {
        "document": deepcopy(document),
        "gate": deepcopy(
            document["gate"]
        ),
        "path": str(policy_path),
    }
