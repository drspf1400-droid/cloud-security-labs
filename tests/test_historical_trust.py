from modules.evidence_signing import (
    generate_ed25519_keypair,
    sign_execution_manifest,
)

from modules.execution_evidence import (
    build_execution_evidence,
)

from modules.trusted_signers import (
    create_registry,
    register_signer_key,
    revoke_signer_key,
    verify_historical_trust,
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
        run_id="RUN-HISTORICAL",
        timestamp=timestamp,
    )


def setup_revoked_key():
    private_key, public_key = (
        generate_ed25519_keypair()
    )

    registry = register_signer_key(
        create_registry(),
        signer_id="security-automation",
        key_id="key-1",
        public_key=public_key,
        registered_at=(
            "2026-09-29T10:00:00+00:00"
        ),
    )

    registry = revoke_signer_key(
        registry,
        next(iter(registry["signers"])),
        reason="Key rotation",
        revoked_at=(
            "2026-09-29T12:00:00+00:00"
        ),
    )

    return private_key, registry


def test_manifest_before_revocation_is_historically_trusted():
    private_key, registry = setup_revoked_key()

    manifest = sign_execution_manifest(
        manifest_at(
            "2026-09-29T11:00:00+00:00"
        ),
        private_key,
    )

    result = verify_historical_trust(
        manifest,
        registry,
    )

    assert result["accepted"] is True
    assert (
        result["status"]
        == "historically_trusted"
    )


def test_manifest_after_revocation_is_rejected():
    private_key, registry = setup_revoked_key()

    manifest = sign_execution_manifest(
        manifest_at(
            "2026-09-29T13:00:00+00:00"
        ),
        private_key,
    )

    result = verify_historical_trust(
        manifest,
        registry,
    )

    assert result["accepted"] is False
    assert (
        result["status"]
        == "revoked_at_signing_time"
    )


def test_manifest_before_registration_is_rejected():
    private_key, registry = setup_revoked_key()

    manifest = sign_execution_manifest(
        manifest_at(
            "2026-09-29T09:00:00+00:00"
        ),
        private_key,
    )

    result = verify_historical_trust(
        manifest,
        registry,
    )

    assert result["accepted"] is False
    assert result["status"] == "before_registration"


def test_invalid_signature_is_rejected():
    private_key, registry = setup_revoked_key()

    manifest = sign_execution_manifest(
        manifest_at(
            "2026-09-29T11:00:00+00:00"
        ),
        private_key,
    )

    manifest["summary"]["blocked"] = 999

    result = verify_historical_trust(
        manifest,
        registry,
    )

    assert result["accepted"] is False
    assert result["status"] == "invalid_signature"


def test_invalid_timestamp_is_rejected():
    private_key, registry = setup_revoked_key()

    manifest = sign_execution_manifest(
        manifest_at(
            "2026-09-29T11:00:00+00:00"
        ),
        private_key,
    )

    manifest["created_at"] = "not-a-date"

    result = verify_historical_trust(
        manifest,
        registry,
    )

    assert result["accepted"] is False
    assert result["status"] == "invalid_timestamp"


def test_pre_revocation_evidence_uses_historical_trust():
    from modules.trusted_signers import (
        evaluate_manifest_trust,
    )

    private_key, registry = setup_revoked_key()

    manifest = sign_execution_manifest(
        manifest_at(
            "2026-09-29T11:00:00+00:00"
        ),
        private_key,
    )

    result = evaluate_manifest_trust(
        manifest,
        registry,
    )

    assert (
        result["current_trust"]["accepted"]
        is False
    )

    assert (
        result["current_trust"]["status"]
        == "revoked"
    )

    assert (
        result["historical_trust"]["accepted"]
        is True
    )

    assert (
        result["effective_trust"]["accepted"]
        is True
    )

    assert (
        result["effective_trust"]["basis"]
        == "historical_trust"
    )


def test_post_revocation_evidence_is_effectively_rejected():
    from modules.trusted_signers import (
        evaluate_manifest_trust,
    )

    private_key, registry = setup_revoked_key()

    manifest = sign_execution_manifest(
        manifest_at(
            "2026-09-29T13:00:00+00:00"
        ),
        private_key,
    )

    result = evaluate_manifest_trust(
        manifest,
        registry,
    )

    assert (
        result["current_trust"]["accepted"]
        is False
    )

    assert (
        result["historical_trust"]["accepted"]
        is False
    )

    assert (
        result["effective_trust"]["accepted"]
        is False
    )

    assert (
        result["effective_trust"]["basis"]
        == "rejected"
    )


def test_active_key_prefers_current_trust():
    from modules.trusted_signers import (
        evaluate_manifest_trust,
    )

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

    manifest = sign_execution_manifest(
        manifest_at(
            "2026-09-29T11:00:00+00:00"
        ),
        private_key,
    )

    result = evaluate_manifest_trust(
        manifest,
        registry,
    )

    assert (
        result["current_trust"]["accepted"]
        is True
    )

    assert (
        result["historical_trust"]["accepted"]
        is True
    )

    assert (
        result["effective_trust"]["basis"]
        == "current_trust"
    )


def test_trust_evaluation_contains_key_lifecycle_audit():
    from modules.evidence_signing import (
        public_key_fingerprint,
    )

    from modules.trusted_signers import (
        evaluate_manifest_trust,
    )

    private_key, public_key = (
        generate_ed25519_keypair()
    )

    fingerprint = public_key_fingerprint(
        public_key
    )

    registry = register_signer_key(
        create_registry(),
        signer_id="security-automation",
        key_id="key-1",
        public_key=public_key,
        registered_at=(
            "2026-09-29T10:00:00+00:00"
        ),
    )

    registry = revoke_signer_key(
        registry,
        fingerprint,
        reason="Rotation",
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

    result = evaluate_manifest_trust(
        manifest,
        registry,
    )

    lifecycle = result["signer_lifecycle"]

    assert lifecycle["signer"]["status"] == "revoked"

    actions = [
        event["action"]
        for event in lifecycle["audit_events"]
    ]

    assert "signer_key_registered" in actions
    assert "signer_key_revoked" in actions
