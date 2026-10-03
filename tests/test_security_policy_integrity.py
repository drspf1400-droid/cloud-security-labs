import json
from copy import deepcopy
from pathlib import Path

from modules.security_policy_integrity import (
    build_policy_integrity_manifest,
    canonical_policy_bytes,
    evaluate_policy_drift,
    policy_fingerprint,
    verify_policy_integrity,
)


ROOT = Path(__file__).resolve().parents[1]

POLICY_DIR = (
    ROOT
    / "policies"
    / "security-gates"
)


def load_policy(environment):
    return json.loads(
        (
            POLICY_DIR
            / f"{environment}.json"
        ).read_text(
            encoding="utf-8"
        )
    )


def all_policies():
    return {
        environment: load_policy(
            environment
        )
        for environment in (
            "lab",
            "staging",
            "production",
        )
    }


def test_fingerprint_is_stable():
    policy = load_policy("production")

    assert (
        policy_fingerprint(policy)
        == policy_fingerprint(policy)
    )


def test_key_order_does_not_change_fingerprint():
    policy = load_policy("production")

    reordered = {
        key: policy[key]
        for key in reversed(
            list(policy.keys())
        )
    }

    assert (
        canonical_policy_bytes(policy)
        == canonical_policy_bytes(reordered)
    )

    assert (
        policy_fingerprint(policy)
        == policy_fingerprint(reordered)
    )


def test_policy_change_changes_fingerprint():
    policy = load_policy("production")
    modified = deepcopy(policy)

    modified["gate"][
        "max_blocked_executions"
    ] = 5

    assert (
        policy_fingerprint(policy)
        != policy_fingerprint(modified)
    )


def test_manifest_contains_all_policies():
    manifest = (
        build_policy_integrity_manifest(
            all_policies(),
            manifest_id="MANIFEST-001",
            created_at=(
                "2026-10-03T10:00:00+00:00"
            ),
        )
    )

    assert manifest["manifest_id"] == (
        "MANIFEST-001"
    )

    assert set(
        manifest["policies"]
    ) == {
        "lab",
        "staging",
        "production",
    }

    assert (
        manifest["algorithm"]
        == "sha256"
    )


def test_unchanged_policy_verifies():
    policies = all_policies()

    manifest = (
        build_policy_integrity_manifest(
            policies
        )
    )

    result = verify_policy_integrity(
        policies["production"],
        manifest["policies"][
            "production"
        ],
        expected_environment="production",
    )

    assert result["matches"] is True
    assert result["status"] == "unchanged"


def test_modified_policy_is_detected_as_drift():
    policies = all_policies()

    manifest = (
        build_policy_integrity_manifest(
            policies
        )
    )

    policies["production"]["gate"][
        "max_blocked_executions"
    ] = 4

    result = evaluate_policy_drift(
        policies,
        manifest,
    )

    assert result["integrity_ok"] is False
    assert result["summary"]["drifted"] == 1

    production = next(
        item
        for item in result["results"]
        if item["environment"]
        == "production"
    )

    assert production["status"] == "drifted"


def test_missing_policy_is_detected():
    policies = all_policies()

    manifest = (
        build_policy_integrity_manifest(
            policies
        )
    )

    del policies["staging"]

    result = evaluate_policy_drift(
        policies,
        manifest,
    )

    assert result["integrity_ok"] is False
    assert result["summary"]["missing"] == 1


def test_all_unchanged_policies_pass_integrity():
    policies = all_policies()

    manifest = (
        build_policy_integrity_manifest(
            policies
        )
    )

    result = evaluate_policy_drift(
        policies,
        manifest,
    )

    assert result["integrity_ok"] is True

    assert result["summary"] == {
        "unchanged": 3,
        "drifted": 0,
        "missing": 0,
        "untrusted": 0,
    }


def test_committed_manifest_matches_current_policies():
    manifest = json.loads(
        (
            POLICY_DIR
            / "trusted-manifest.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    result = evaluate_policy_drift(
        all_policies(),
        manifest,
    )

    assert result["integrity_ok"] is True

    assert result["summary"] == {
        "unchanged": 3,
        "drifted": 0,
        "missing": 0,
        "untrusted": 0,
    }
