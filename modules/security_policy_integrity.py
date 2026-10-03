#!/usr/bin/env python3

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from uuid import uuid4

try:
    from modules.security_gate_policy import (
        validate_security_gate_policy,
    )
except ModuleNotFoundError:
    from security_gate_policy import (
        validate_security_gate_policy,
    )


MANIFEST_VERSION = "1.0"
HASH_ALGORITHM = "sha256"


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


def canonical_policy_bytes(policy):
    """
    Return a deterministic JSON representation.

    Whitespace and key ordering do not affect the
    resulting fingerprint.
    """
    return json.dumps(
        policy,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def policy_fingerprint(policy):
    """
    Calculate the SHA-256 fingerprint of a policy.
    """
    return hashlib.sha256(
        canonical_policy_bytes(policy)
    ).hexdigest()


def build_policy_integrity_manifest(
    policies,
    *,
    manifest_id=None,
    created_at=None,
):
    """
    Build a trusted fingerprint manifest.

    policies:
        {
            "lab": <policy document>,
            "staging": <policy document>,
            "production": <policy document>
        }
    """

    source = deepcopy(policies)

    if manifest_id is None:
        manifest_id = str(uuid4())

    if created_at is None:
        created_at = utc_now()

    entries = {}

    for environment in sorted(source):
        document = source[environment]

        validate_security_gate_policy(
            document,
            expected_environment=environment,
        )

        entries[environment] = {
            "policy_name": document.get(
                "policy_name"
            ),
            "policy_version": document.get(
                "policy_version"
            ),
            "fingerprint": policy_fingerprint(
                document
            ),
        }

    return {
        "manifest_version": MANIFEST_VERSION,
        "manifest_id": manifest_id,
        "created_at": created_at,
        "algorithm": HASH_ALGORITHM,
        "policies": entries,
    }


def verify_policy_integrity(
    policy,
    trusted_entry,
    *,
    expected_environment=None,
):
    """
    Compare a policy against a trusted manifest entry.
    """

    source = deepcopy(policy)
    trusted = deepcopy(trusted_entry)

    validate_security_gate_policy(
        source,
        expected_environment=(
            expected_environment
        ),
    )

    actual = policy_fingerprint(source)

    expected = trusted.get(
        "fingerprint"
    )

    matches = (
        isinstance(expected, str)
        and actual == expected
    )

    return {
        "environment": source.get(
            "environment"
        ),
        "policy_name": source.get(
            "policy_name"
        ),
        "policy_version": source.get(
            "policy_version"
        ),
        "algorithm": HASH_ALGORITHM,
        "expected_fingerprint": expected,
        "actual_fingerprint": actual,
        "matches": matches,
        "status": (
            "unchanged"
            if matches
            else "drifted"
        ),
    }


def evaluate_policy_drift(
    current_policies,
    trusted_manifest,
):
    """
    Compare the current policy set with a trusted
    integrity manifest.
    """

    current = deepcopy(current_policies)
    manifest = deepcopy(trusted_manifest)

    if (
        manifest.get("manifest_version")
        != MANIFEST_VERSION
    ):
        raise ValueError(
            "Unsupported policy integrity "
            "manifest version"
        )

    if (
        manifest.get("algorithm")
        != HASH_ALGORITHM
    ):
        raise ValueError(
            "Unsupported policy integrity "
            "hash algorithm"
        )

    trusted_entries = manifest.get(
        "policies",
        {},
    )

    results = []

    all_environments = sorted(
        set(current)
        | set(trusted_entries)
    )

    for environment in all_environments:
        current_policy = current.get(
            environment
        )

        trusted_entry = trusted_entries.get(
            environment
        )

        if current_policy is None:
            results.append(
                {
                    "environment": environment,
                    "status": "missing",
                    "matches": False,
                }
            )
            continue

        if trusted_entry is None:
            validate_security_gate_policy(
                current_policy,
                expected_environment=(
                    environment
                ),
            )

            results.append(
                {
                    "environment": environment,
                    "policy_name": (
                        current_policy.get(
                            "policy_name"
                        )
                    ),
                    "status": "untrusted",
                    "matches": False,
                    "actual_fingerprint": (
                        policy_fingerprint(
                            current_policy
                        )
                    ),
                }
            )
            continue

        results.append(
            verify_policy_integrity(
                current_policy,
                trusted_entry,
                expected_environment=(
                    environment
                ),
            )
        )

    summary = {
        "unchanged": sum(
            item["status"] == "unchanged"
            for item in results
        ),
        "drifted": sum(
            item["status"] == "drifted"
            for item in results
        ),
        "missing": sum(
            item["status"] == "missing"
            for item in results
        ),
        "untrusted": sum(
            item["status"] == "untrusted"
            for item in results
        ),
    }

    integrity_ok = (
        summary["drifted"] == 0
        and summary["missing"] == 0
        and summary["untrusted"] == 0
    )

    return {
        "manifest_id": manifest.get(
            "manifest_id"
        ),
        "algorithm": HASH_ALGORITHM,
        "integrity_ok": integrity_ok,
        "summary": summary,
        "results": results,
    }
