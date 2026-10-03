import json
import shutil

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

import modules.policy_rotation_promotion as promotion

from modules.policy_key_rotation import (
    execute_policy_key_rotation,
    plan_policy_key_rotation,
)

from modules.approver_trust_registry import (
    create_approver_registry,
    register_approver,
)

from modules.policy_manifest_signing import (
    public_key_to_base64,
)

from modules.rotation_approval import (
    sign_rotation_approval,
)

from modules.policy_signer_registry import (
    policy_signer_registry_fingerprint,
)


ROOT = promotion.Path(
    __file__
).resolve().parents[1]

POLICY_DIR = (
    ROOT
    / "policies"
    / "security-gates"
)


def build_candidate(tmp_path):
    manifest = json.loads(
        (
            POLICY_DIR
            / "trusted-manifest.json"
        ).read_text()
    )

    registry = json.loads(
        (
            POLICY_DIR
            / "trusted-policy-signers.json"
        ).read_text()
    )

    old_fingerprint = (
        manifest["signature"][
            "key_fingerprint"
        ]
    )

    new_key = Ed25519PrivateKey.generate()

    from datetime import (
        datetime,
        timedelta,
    )

    created = datetime.fromisoformat(
        manifest["created_at"]
    )

    rotated_at = (
        created
        + timedelta(hours=1)
    ).isoformat()

    plan = plan_policy_key_rotation(
        manifest,
        registry,
        old_fingerprint=old_fingerprint,
        new_private_key=new_key,
        new_signer_id=(
            "security-policy-authority"
        ),
        new_key_id=(
            "policy-manifest-key-test-002"
        ),
        rotated_at=rotated_at,
        initiated_by="security-operator",
        rotation_id="PROMOTION-TEST-001",
        new_manifest_id=(
            "PROMOTION-MANIFEST-002"
        ),
    )

    approver_key = (
        Ed25519PrivateKey.generate()
    )

    approval = sign_rotation_approval(
        plan,
        approver_key,
        initiated_by=plan["initiated_by"],
        approved_by="test-approver",
        approved_at=rotated_at,
        approval_id="PROMOTION-APPROVAL-001",
    )

    approver_registry = (
        create_approver_registry(
            created_at=(
                "2026-10-03T10:00:00+00:00"
            ),
            registry_id=(
                "PROMOTION-APPROVER-REGISTRY-001"
            ),
        )
    )

    approver_registry = register_approver(
        approver_registry,
        approver_id="test-approver",
        key_id="approver-key-001",
        public_key_b64=(
            public_key_to_base64(
                approver_key.public_key()
            )
        ),
        registered_at=(
            "2026-10-03T10:30:00+00:00"
        ),
    )

    result = execute_policy_key_rotation(
        plan,
        manifest,
        registry,
        new_key,
        approval=approval,
        approver_registry=(
            approver_registry
        ),
    )

    result["_test_plan"] = plan
    result["_test_approval"] = approval
    result[
        "_test_approver_registry"
    ] = approver_registry

    candidate_dir = (
        tmp_path
        / "candidate"
    )

    candidate_dir.mkdir()

    candidate_manifest = (
        candidate_dir
        / "trusted-manifest.json"
    )

    candidate_registry = (
        candidate_dir
        / "trusted-policy-signers.json"
    )

    candidate_manifest.write_text(
        json.dumps(
            result["manifest"],
            indent=2,
        )
        + "\n"
    )

    candidate_registry.write_text(
        json.dumps(
            result["registry"],
            indent=2,
        )
        + "\n"
    )

    return (
        candidate_manifest,
        candidate_registry,
        result,
    )


def current_files(tmp_path):
    current_dir = tmp_path / "current"

    current_dir.mkdir()

    manifest = (
        current_dir
        / "trusted-manifest.json"
    )

    registry = (
        current_dir
        / "trusted-policy-signers.json"
    )

    shutil.copy(
        POLICY_DIR
        / "trusted-manifest.json",
        manifest,
    )

    shutil.copy(
        POLICY_DIR
        / "trusted-policy-signers.json",
        registry,
    )

    return manifest, registry


def test_valid_rotation_candidate_is_accepted(
    tmp_path,
):
    candidate_manifest, candidate_registry, rotation_result = (
        build_candidate(tmp_path)
    )

    manifest, registry = current_files(
        tmp_path
    )

    result = (
        promotion.validate_rotation_candidate(
            json.loads(manifest.read_text()),
            json.loads(registry.read_text()),
            json.loads(
                candidate_manifest.read_text()
            ),
            json.loads(
                candidate_registry.read_text()
            ),
        )
    )

    assert result["valid"] is True

    assert (
        result["candidate_trust_basis"]
        == "current_trust"
    )

    assert (
        result["old_manifest_trust_basis"]
        == "historical_trust"
    )


def test_promotion_replaces_trust_files(
    tmp_path,
):
    candidate_manifest, candidate_registry, rotation_result = (
        build_candidate(tmp_path)
    )

    manifest, registry = current_files(
        tmp_path
    )

    promotion.promote_policy_rotation(
        plan=rotation_result["_test_plan"],
        approval=(
            rotation_result["_test_approval"]
        ),
        approver_registry=(
            rotation_result[
                "_test_approver_registry"
            ]
        ),
        current_manifest_path=manifest,
        current_registry_path=registry,
        candidate_manifest_path=(
            candidate_manifest
        ),
        candidate_registry_path=(
            candidate_registry
        ),
        backup_dir=tmp_path / "backup",
        promoted_by="security-admin",
    )

    assert (
        manifest.read_bytes()
        == candidate_manifest.read_bytes()
    )

    assert (
        registry.read_bytes()
        == candidate_registry.read_bytes()
    )


def test_promotion_creates_backups(
    tmp_path,
):
    candidate_manifest, candidate_registry, rotation_result = (
        build_candidate(tmp_path)
    )

    manifest, registry = current_files(
        tmp_path
    )

    backup = tmp_path / "backup"

    promotion.promote_policy_rotation(
        plan=rotation_result["_test_plan"],
        approval=(
            rotation_result["_test_approval"]
        ),
        approver_registry=(
            rotation_result[
                "_test_approver_registry"
            ]
        ),
        current_manifest_path=manifest,
        current_registry_path=registry,
        candidate_manifest_path=(
            candidate_manifest
        ),
        candidate_registry_path=(
            candidate_registry
        ),
        backup_dir=backup,
        promoted_by="security-admin",
    )

    assert (
        backup
        / "trusted-manifest.before-rotation.json"
    ).exists()

    assert (
        backup
        / "trusted-policy-signers.before-rotation.json"
    ).exists()


def test_promotion_writes_audit_evidence(
    tmp_path,
):
    candidate_manifest, candidate_registry, rotation_result = (
        build_candidate(tmp_path)
    )

    manifest, registry = current_files(
        tmp_path
    )

    audit_path = (
        tmp_path
        / "promotion-audit.json"
    )

    audit = promotion.promote_policy_rotation(
        plan=rotation_result["_test_plan"],
        approval=(
            rotation_result["_test_approval"]
        ),
        approver_registry=(
            rotation_result[
                "_test_approver_registry"
            ]
        ),
        current_manifest_path=manifest,
        current_registry_path=registry,
        candidate_manifest_path=(
            candidate_manifest
        ),
        candidate_registry_path=(
            candidate_registry
        ),
        backup_dir=tmp_path / "backup",
        audit_path=audit_path,
        promoted_by="security-admin",
    )

    assert audit_path.exists()

    assert (
        audit["promoted_by"]
        == "security-admin"
    )

    candidate = json.loads(
        candidate_registry.read_text()
    )

    assert (
        audit["new_registry_sha256"]
        == policy_signer_registry_fingerprint(
            candidate
        )
    )


def test_invalid_candidate_does_not_modify_current_files(
    tmp_path,
):
    candidate_manifest, candidate_registry, rotation_result = (
        build_candidate(tmp_path)
    )

    manifest, registry = current_files(
        tmp_path
    )

    original_manifest = (
        manifest.read_bytes()
    )

    original_registry = (
        registry.read_bytes()
    )

    tampered = json.loads(
        candidate_manifest.read_text()
    )

    tampered["manifest_id"] = (
        "TAMPERED"
    )

    candidate_manifest.write_text(
        json.dumps(
            tampered,
            indent=2,
        )
        + "\n"
    )

    with pytest.raises(
        promotion.PolicyRotationPromotionError
    ):
        promotion.promote_policy_rotation(
            plan=rotation_result["_test_plan"],
            approval=(
                rotation_result["_test_approval"]
            ),
            approver_registry=(
                rotation_result[
                    "_test_approver_registry"
                ]
            ),
            current_manifest_path=manifest,
            current_registry_path=registry,
            candidate_manifest_path=(
                candidate_manifest
            ),
            candidate_registry_path=(
                candidate_registry
            ),
            backup_dir=tmp_path / "backup",
            promoted_by="security-admin",
        )

    assert (
        manifest.read_bytes()
        == original_manifest
    )

    assert (
        registry.read_bytes()
        == original_registry
    )


def test_failure_during_promotion_rolls_back(
    tmp_path,
    monkeypatch,
):
    candidate_manifest, candidate_registry, rotation_result = (
        build_candidate(tmp_path)
    )

    manifest, registry = current_files(
        tmp_path
    )

    original_manifest = (
        manifest.read_bytes()
    )

    original_registry = (
        registry.read_bytes()
    )

    real_replace = promotion.os.replace
    calls = {"count": 0}

    def fail_once(source, destination):
        calls["count"] += 1

        if calls["count"] == 2:
            raise OSError(
                "simulated promotion failure"
            )

        return real_replace(
            source,
            destination,
        )

    monkeypatch.setattr(
        promotion.os,
        "replace",
        fail_once,
    )

    with pytest.raises(
        promotion.PolicyRotationPromotionError,
        match="previous trust state was restored",
    ):
        promotion.promote_policy_rotation(
            plan=rotation_result["_test_plan"],
            approval=(
                rotation_result["_test_approval"]
            ),
            approver_registry=(
                rotation_result[
                    "_test_approver_registry"
                ]
            ),
            current_manifest_path=manifest,
            current_registry_path=registry,
            candidate_manifest_path=(
                candidate_manifest
            ),
            candidate_registry_path=(
                candidate_registry
            ),
            backup_dir=tmp_path / "backup",
            promoted_by="security-admin",
        )

    assert (
        manifest.read_bytes()
        == original_manifest
    )

    assert (
        registry.read_bytes()
        == original_registry
    )


def test_candidate_artifacts_are_not_modified(
    tmp_path,
):
    candidate_manifest, candidate_registry, rotation_result = (
        build_candidate(tmp_path)
    )

    manifest, registry = current_files(
        tmp_path
    )

    manifest_before = (
        candidate_manifest.read_bytes()
    )

    registry_before = (
        candidate_registry.read_bytes()
    )

    promotion.promote_policy_rotation(
        plan=rotation_result["_test_plan"],
        approval=(
            rotation_result["_test_approval"]
        ),
        approver_registry=(
            rotation_result[
                "_test_approver_registry"
            ]
        ),
        current_manifest_path=manifest,
        current_registry_path=registry,
        candidate_manifest_path=(
            candidate_manifest
        ),
        candidate_registry_path=(
            candidate_registry
        ),
        backup_dir=tmp_path / "backup",
        promoted_by="security-admin",
    )

    assert (
        candidate_manifest.read_bytes()
        == manifest_before
    )

    assert (
        candidate_registry.read_bytes()
        == registry_before
    )
