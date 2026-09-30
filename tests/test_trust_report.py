import json
from copy import deepcopy

from modules.evidence_signing import (
    generate_ed25519_keypair,
    sign_execution_manifest,
)

from modules.execution_evidence import (
    build_execution_evidence,
)

from modules.trust_report import (
    build_trust_decision_report,
)

from modules.trusted_signers import (
    create_registry,
    register_signer_key,
    revoke_signer_key,
)


def manifest_at(timestamp):
    execution_result = {
        "environment": "lab",
        "summary": {
            "executed": 0,
            "dry_run": 0,
            "blocked": 1,
            "failed": 0,
        },
        "results": [
            {
                "finding_id": "UNKNOWN-001",
                "decision": "blocked",
                "action": None,
                "status": "blocked",
                "reason": "Blocked by policy.",
            }
        ],
        "assessment": {
            "findings": []
        },
    }

    return build_execution_evidence(
        execution_result,
        actor="tester",
        run_id="RUN-REPORT-001",
        timestamp=timestamp,
    )


def active_signer():
    private_key, public_key = (
        generate_ed25519_keypair()
    )

    registry = register_signer_key(
        create_registry(),
        signer_id="security-automation",
        key_id="key-active",
        public_key=public_key,
        registered_at=(
            "2026-09-29T10:00:00+00:00"
        ),
    )

    return private_key, registry


def test_active_signer_report_is_accepted():
    private_key, registry = active_signer()

    manifest = sign_execution_manifest(
        manifest_at(
            "2026-09-29T11:00:00+00:00"
        ),
        private_key,
    )

    report = build_trust_decision_report(
        manifest,
        registry,
        report_id="REPORT-001",
        generated_at=(
            "2026-09-29T11:05:00+00:00"
        ),
    )

    assert report["report_version"] == "1.0"
    assert report["report_id"] == "REPORT-001"

    assert (
        report["verification"]
        ["effective_decision"]
        == "accept"
    )

    assert (
        report["verification"]
        ["decision_basis"]
        == "current_trust"
    )

    assert (
        report["verification"]
        ["signature_valid"]
        is True
    )


def test_pre_revocation_report_uses_historical_trust():
    private_key, registry = active_signer()

    fingerprint = next(
        iter(registry["signers"])
    )

    registry = revoke_signer_key(
        registry,
        fingerprint,
        reason="Key rotation",
        revoked_at=(
            "2026-09-29T12:00:00+00:00"
        ),
    )

    manifest = sign_execution_manifest(
        manifest_at(
            "2026-09-29T11:00:00+00:00"
        ),
        private_key,
    )

    report = build_trust_decision_report(
        manifest,
        registry,
    )

    assert (
        report["verification"]
        ["current_trust"]["accepted"]
        is False
    )

    assert (
        report["verification"]
        ["historical_trust"]["accepted"]
        is True
    )

    assert (
        report["verification"]
        ["effective_decision"]
        == "accept"
    )

    assert (
        report["verification"]
        ["decision_basis"]
        == "historical_trust"
    )


def test_post_revocation_report_is_rejected():
    private_key, registry = active_signer()

    fingerprint = next(
        iter(registry["signers"])
    )

    registry = revoke_signer_key(
        registry,
        fingerprint,
        reason="Key rotation",
        revoked_at=(
            "2026-09-29T12:00:00+00:00"
        ),
    )

    manifest = sign_execution_manifest(
        manifest_at(
            "2026-09-29T13:00:00+00:00"
        ),
        private_key,
    )

    report = build_trust_decision_report(
        manifest,
        registry,
    )

    assert (
        report["verification"]
        ["effective_decision"]
        == "reject"
    )

    assert (
        report["verification"]
        ["decision_basis"]
        == "rejected"
    )


def test_report_contains_signer_lifecycle_metadata():
    private_key, registry = active_signer()

    fingerprint = next(
        iter(registry["signers"])
    )

    registry = revoke_signer_key(
        registry,
        fingerprint,
        reason="Compromised key",
        revoked_at=(
            "2026-09-29T12:00:00+00:00"
        ),
    )

    manifest = sign_execution_manifest(
        manifest_at(
            "2026-09-29T11:00:00+00:00"
        ),
        private_key,
    )

    report = build_trust_decision_report(
        manifest,
        registry,
    )

    assert (
        report["signer"]["key_status"]
        == "revoked"
    )

    assert (
        report["signer"]["revocation_reason"]
        == "Compromised key"
    )

    actions = [
        event["action"]
        for event in report["lifecycle_audit"]
    ]

    assert "signer_key_registered" in actions
    assert "signer_key_revoked" in actions


def test_report_does_not_mutate_inputs():
    private_key, registry = active_signer()

    manifest = sign_execution_manifest(
        manifest_at(
            "2026-09-29T11:00:00+00:00"
        ),
        private_key,
    )

    original_manifest = deepcopy(manifest)
    original_registry = deepcopy(registry)

    build_trust_decision_report(
        manifest,
        registry,
    )

    assert manifest == original_manifest
    assert registry == original_registry


def test_report_is_json_serializable():
    private_key, registry = active_signer()

    manifest = sign_execution_manifest(
        manifest_at(
            "2026-09-29T11:00:00+00:00"
        ),
        private_key,
    )

    report = build_trust_decision_report(
        manifest,
        registry,
    )

    serialized = json.dumps(report)
    restored = json.loads(serialized)

    assert restored == report


def test_accepted_trust_report_matches_schema():
    from pathlib import Path
    from jsonschema import validate

    private_key, registry = active_signer()

    manifest = sign_execution_manifest(
        manifest_at(
            "2026-09-29T11:00:00+00:00"
        ),
        private_key,
    )

    report = build_trust_decision_report(
        manifest,
        registry,
        report_id="REPORT-SCHEMA-ACCEPT",
        generated_at=(
            "2026-09-29T11:05:00+00:00"
        ),
    )

    schema = json.loads(
        Path(
            "schemas/trust-decision-report-schema.json"
        ).read_text()
    )

    validate(
        instance=report,
        schema=schema,
    )


def test_rejected_trust_report_matches_schema():
    from pathlib import Path
    from jsonschema import validate

    private_key, registry = active_signer()

    fingerprint = next(
        iter(registry["signers"])
    )

    registry = revoke_signer_key(
        registry,
        fingerprint,
        reason="Compromised key",
        revoked_at=(
            "2026-09-29T12:00:00+00:00"
        ),
    )

    manifest = sign_execution_manifest(
        manifest_at(
            "2026-09-29T13:00:00+00:00"
        ),
        private_key,
    )

    report = build_trust_decision_report(
        manifest,
        registry,
        report_id="REPORT-SCHEMA-REJECT",
        generated_at=(
            "2026-09-29T13:05:00+00:00"
        ),
    )

    schema = json.loads(
        Path(
            "schemas/trust-decision-report-schema.json"
        ).read_text()
    )

    validate(
        instance=report,
        schema=schema,
    )
