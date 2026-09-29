#!/usr/bin/env python3

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from uuid import uuid4


MANIFEST_VERSION = "1.0"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def canonical_manifest_payload(manifest):
    payload = deepcopy(manifest)
    payload.pop("integrity", None)
    payload.pop("provenance", None)

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def calculate_manifest_hash(manifest):
    return hashlib.sha256(
        canonical_manifest_payload(manifest)
    ).hexdigest()


def verify_manifest_integrity(manifest):
    integrity = manifest.get("integrity", {})

    expected = integrity.get("sha256")

    if not expected:
        return False

    actual = calculate_manifest_hash(manifest)

    return actual == expected


def build_execution_evidence(
    execution_result,
    actor,
    run_id=None,
    timestamp=None,
):
    """
    Build an immutable-style evidence manifest from
    an execution-engine result.

    This function does not mutate the execution result.
    """
    source = deepcopy(execution_result)

    if run_id is None:
        run_id = str(uuid4())

    if timestamp is None:
        timestamp = utc_now()

    assessment = source.get("assessment", {})

    findings = {
        finding.get("finding_id"): finding
        for finding in assessment.get("findings", [])
    }

    evidence_items = []

    for result in source.get("results", []):
        finding_id = result.get("finding_id")
        finding = findings.get(finding_id, {})

        remediation = finding.get(
            "remediation",
            {},
        )

        finding_audit = finding.get(
            "audit_trail",
            [],
        )

        audit_actions = [
            entry.get("action")
            for entry in finding_audit
            if entry.get("action") is not None
        ]

        evidence_items.append({
            "finding_id": finding_id,
            "decision": result.get("decision"),
            "action": result.get("action"),
            "execution_status": result.get("status"),
            "reason": result.get("reason"),
            "final_finding_status": finding.get("status"),
            "remediation_applied": remediation.get(
                "applied",
                False,
            ),
            "verification_passed": (
                "verification_passed"
                in audit_actions
            ),
            "verification_failed": (
                "verification_failed"
                in audit_actions
            ),
            "rollback_performed": remediation.get(
                "rollback_performed",
                False,
            ),
            "rollback_verified": remediation.get(
                "rollback_verified",
                False,
            ),
            "finding_audit_events": audit_actions,
        })

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "run_id": run_id,
        "created_at": timestamp,
        "actor": actor,
        "environment": source.get(
            "environment",
            "unknown",
        ),
        "summary": deepcopy(
            source.get("summary", {})
        ),
        "evidence": evidence_items,
    }

    manifest["integrity"] = {
        "algorithm": "sha256",
        "sha256": calculate_manifest_hash(
            manifest
        ),
    }

    return manifest
