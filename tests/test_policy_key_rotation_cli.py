import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


ROOT = Path(__file__).resolve().parents[1]

SCRIPT = (
    ROOT
    / "scripts"
    / "rotate_policy_signing_key.py"
)

MANIFEST = (
    ROOT
    / "policies"
    / "security-gates"
    / "trusted-manifest.json"
)

REGISTRY = (
    ROOT
    / "policies"
    / "security-gates"
    / "trusted-policy-signers.json"
)


def run_cli(*args):
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            *map(str, args),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def create_private_key(path):
    key = Ed25519PrivateKey.generate()

    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=(
                serialization.NoEncryption()
            ),
        )
    )

    return key



def create_cli_signed_approval(
    tmp_path,
    plan_path,
    *,
    stem,
):
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
    )

    from modules.approver_trust_registry import (
        create_approver_registry,
        register_approver,
    )

    from modules.policy_manifest_signing import (
        public_key_to_base64,
    )

    private_key_path = (
        tmp_path
        / f"{stem}-approver-private.pem"
    )

    approval_path = (
        tmp_path
        / f"{stem}-approval.json"
    )

    registry_path = (
        tmp_path
        / f"{stem}-approver-registry.json"
    )

    create_private_key(
        private_key_path
    )

    private_key = (
        load_pem_private_key(
            private_key_path.read_bytes(),
            password=None,
        )
    )

    registry = create_approver_registry(
        created_at=(
            "2026-10-04T08:00:00+00:00"
        ),
        registry_id=(
            f"{stem.upper()}-APPROVER-REGISTRY-001"
        ),
    )

    registry = register_approver(
        registry,
        approver_id="security-admin",
        key_id="approver-key-001",
        public_key_b64=(
            public_key_to_base64(
                private_key.public_key()
            )
        ),
        registered_at=(
            "2026-10-04T08:30:00+00:00"
        ),
    )

    registry_path.write_text(
        json.dumps(
            registry,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    approval = run_cli(
        "approve",
        "--plan",
        plan_path,
        "--approver-private-key",
        private_key_path,
        "--approved-by",
        "security-admin",
        "--approved-at",
        "2026-10-04T09:30:00+00:00",
        "--approval-id",
        f"{stem.upper()}-APPROVAL-001",
        "--output",
        approval_path,
    )

    assert approval.returncode == 0, (
        approval.stderr
    )

    return (
        approval_path,
        registry_path,
    )


def create_plan(tmp_path):
    key_path = (
        tmp_path
        / "new-key.pem"
    )

    create_private_key(
        key_path
    )

    plan_path = (
        tmp_path
        / "rotation-plan.json"
    )

    manifest = json.loads(
        MANIFEST.read_text(
            encoding="utf-8"
        )
    )

    rotated_at = (
        "2026-10-04T10:00:00+00:00"
    )

    result = run_cli(
        "plan",
        "--manifest",
        MANIFEST,
        "--registry",
        REGISTRY,
        "--new-private-key",
        key_path,
        "--initiated-by",
        "security-operator",
        "--new-signer-id",
        "security-policy-authority",
        "--new-key-id",
        "policy-manifest-key-002",
        "--rotated-at",
        rotated_at,
        "--rotation-id",
        "ROTATION-CLI-001",
        "--new-manifest-id",
        "POLICY-MANIFEST-002",
        "--output",
        plan_path,
    )

    if (
        result.returncode == 0
        and plan_path.exists()
    ):
        create_cli_signed_approval(
            tmp_path,
            plan_path,
            stem="execute",
        )

    return (
        result,
        key_path,
        plan_path,
        manifest,
    )


def test_cli_creates_rotation_plan(
    tmp_path,
):
    result, _, plan_path, _ = (
        create_plan(tmp_path)
    )

    assert result.returncode == 0

    assert (
        "Policy key rotation plan created"
        in result.stdout
    )

    assert plan_path.exists()

    plan = json.loads(
        plan_path.read_text(
            encoding="utf-8"
        )
    )

    assert plan["status"] == "planned"

    assert (
        plan["requires_approval"]
        is True
    )

    assert (
        plan["new_signer"]["key_id"]
        == "policy-manifest-key-002"
    )


def test_plan_contains_no_private_key(
    tmp_path,
):
    _, _, plan_path, _ = (
        create_plan(tmp_path)
    )

    plan_text = plan_path.read_text(
        encoding="utf-8"
    ).lower()

    assert "private_key" not in plan_text
    assert "private key" not in plan_text
    assert "begin private key" not in plan_text



def test_execute_requires_signed_approval(
    tmp_path,
):
    result, key_path, plan_path, _ = (
        create_plan(tmp_path)
    )

    assert result.returncode == 0

    execute = run_cli(
        "execute",
        "--plan",
        plan_path,
        "--manifest",
        MANIFEST,
        "--registry",
        REGISTRY,
        "--new-private-key",
        key_path,
        "--output-dir",
        tmp_path / "candidate",
    )

    assert execute.returncode == 2

    assert (
        "--approval"
        in execute.stderr
    )

def test_approved_execution_creates_artifacts(
    tmp_path,
):
    result, key_path, plan_path, _ = (
        create_plan(tmp_path)
    )

    assert result.returncode == 0

    output_dir = (
        tmp_path
        / "rotation-output"
    )

    execute = run_cli(
        "execute",
        "--plan",
        plan_path,
        "--manifest",
        MANIFEST,
        "--registry",
        REGISTRY,
        "--new-private-key",
        key_path,
        "--approval",
        tmp_path / "execute-approval.json",
        "--approver-registry",
        tmp_path / "execute-approver-registry.json",
        "--output-dir",
        output_dir,
    )

    assert execute.returncode == 0

    assert (
        "Policy key rotation completed"
        in execute.stdout
    )

    expected = {
        "trusted-policy-signers.json",
        "trusted-manifest.json",
        "policy-key-rotation-audit.json",
        "policy-key-rotation-result.json",
    }

    assert {
        path.name
        for path in output_dir.iterdir()
    } == expected


def test_rotated_registry_revokes_old_signer(
    tmp_path,
):
    _, key_path, plan_path, _ = (
        create_plan(tmp_path)
    )

    output_dir = tmp_path / "output"

    execute = run_cli(
        "execute",
        "--plan",
        plan_path,
        "--manifest",
        MANIFEST,
        "--registry",
        REGISTRY,
        "--new-private-key",
        key_path,
        "--approval",
        tmp_path / "execute-approval.json",
        "--approver-registry",
        tmp_path / "execute-approver-registry.json",
        "--output-dir",
        output_dir,
    )

    assert execute.returncode == 0

    registry = json.loads(
        (
            output_dir
            / "trusted-policy-signers.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    statuses = {
        signer["key_id"]:
        signer["status"]
        for signer in registry["signers"]
    }

    assert (
        statuses[
            "policy-manifest-key-001"
        ]
        == "revoked"
    )

    assert (
        statuses[
            "policy-manifest-key-002"
        ]
        == "active"
    )


def test_rotated_manifest_uses_new_key(
    tmp_path,
):
    _, key_path, plan_path, _ = (
        create_plan(tmp_path)
    )

    output_dir = tmp_path / "output"

    execute = run_cli(
        "execute",
        "--plan",
        plan_path,
        "--manifest",
        MANIFEST,
        "--registry",
        REGISTRY,
        "--new-private-key",
        key_path,
        "--approval",
        tmp_path / "execute-approval.json",
        "--approver-registry",
        tmp_path / "execute-approver-registry.json",
        "--output-dir",
        output_dir,
    )

    assert execute.returncode == 0

    manifest = json.loads(
        (
            output_dir
            / "trusted-manifest.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    assert (
        manifest["signature"]["key_id"]
        == "policy-manifest-key-002"
    )

    assert (
        manifest["manifest_id"]
        == "POLICY-MANIFEST-002"
    )


def test_rotation_result_records_approval(
    tmp_path,
):
    _, key_path, plan_path, _ = (
        create_plan(tmp_path)
    )

    output_dir = tmp_path / "output"

    execute = run_cli(
        "execute",
        "--plan",
        plan_path,
        "--manifest",
        MANIFEST,
        "--registry",
        REGISTRY,
        "--new-private-key",
        key_path,
        "--approval",
        tmp_path / "execute-approval.json",
        "--approver-registry",
        tmp_path / "execute-approver-registry.json",
        "--output-dir",
        output_dir,
    )

    assert execute.returncode == 0

    result = json.loads(
        (
            output_dir
            / "policy-key-rotation-result.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    assert (
        result["approved_by"]
        == "security-admin"
    )

    assert result["status"] == "completed"

    assert (
        result["verification"]["accepted"]
        is True
    )

    assert (
        result["verification"]["basis"]
        == "current_trust"
    )



def prepare_promotion_state(tmp_path):
    import shutil

    result, key_path, plan_path, _ = (
        create_plan(tmp_path)
    )

    assert result.returncode == 0

    promotion_plan = (
        tmp_path
        / "promotion-plan.json"
    )

    shutil.copy(
        plan_path,
        promotion_plan,
    )

    (
        approval_path,
        approver_registry,
    ) = create_cli_signed_approval(
        tmp_path,
        promotion_plan,
        stem="promotion",
    )

    candidate_dir = (
        tmp_path
        / "candidate"
    )

    execute = run_cli(
        "execute",
        "--plan",
        promotion_plan,
        "--manifest",
        MANIFEST,
        "--registry",
        REGISTRY,
        "--new-private-key",
        key_path,
        "--approval",
        approval_path,
        "--approver-registry",
        approver_registry,
        "--output-dir",
        candidate_dir,
    )

    assert execute.returncode == 0, (
        execute.stderr
    )

    current_dir = (
        tmp_path
        / "current"
    )

    current_dir.mkdir()

    current_manifest = (
        current_dir
        / "trusted-manifest.json"
    )

    current_registry = (
        current_dir
        / "trusted-policy-signers.json"
    )

    shutil.copy(
        MANIFEST,
        current_manifest,
    )

    shutil.copy(
        REGISTRY,
        current_registry,
    )

    return (
        candidate_dir,
        current_manifest,
        current_registry,
    )


def test_promote_requires_signed_approval(
    tmp_path,
):
    (
        candidate_dir,
        current_manifest,
        current_registry,
    ) = prepare_promotion_state(
        tmp_path
    )

    result = run_cli(
        "promote",
        "--current-manifest",
        current_manifest,
        "--current-registry",
        current_registry,
        "--candidate-manifest",
        candidate_dir
        / "trusted-manifest.json",
        "--candidate-registry",
        candidate_dir
        / "trusted-policy-signers.json",
        "--backup-dir",
        tmp_path / "backup",
        "--audit-output",
        tmp_path / "audit.json",
        "--promoted-by",
        "security-admin",
    )

    assert result.returncode == 2

    assert (
        "--approval"
        in result.stderr
    )

def test_promote_replaces_current_files(
    tmp_path,
):
    (
        candidate_dir,
        current_manifest,
        current_registry,
    ) = prepare_promotion_state(
        tmp_path
    )

    candidate_manifest = (
        candidate_dir
        / "trusted-manifest.json"
    )

    candidate_registry = (
        candidate_dir
        / "trusted-policy-signers.json"
    )

    result = run_cli(
        "promote",
        "--current-manifest",
        current_manifest,
        "--current-registry",
        current_registry,
        "--candidate-manifest",
        candidate_manifest,
        "--candidate-registry",
        candidate_registry,
        "--backup-dir",
        tmp_path / "backup",
        "--audit-output",
        tmp_path / "promotion-audit.json",
        "--promoted-by",
        "security-admin",
        "--promoted-at",
        "2026-10-04T11:00:00+00:00",
        "--plan",
        tmp_path / "promotion-plan.json",
        "--approval",
        tmp_path / "promotion-approval.json",
        "--approver-registry",
        tmp_path / "promotion-approver-registry.json",
    )

    assert result.returncode == 0

    assert (
        "Policy key rotation promoted"
        in result.stdout
    )

    assert (
        current_manifest.read_bytes()
        == candidate_manifest.read_bytes()
    )

    assert (
        current_registry.read_bytes()
        == candidate_registry.read_bytes()
    )


def test_promote_creates_audit_and_backups(
    tmp_path,
):
    (
        candidate_dir,
        current_manifest,
        current_registry,
    ) = prepare_promotion_state(
        tmp_path
    )

    backup_dir = tmp_path / "backup"

    audit_path = (
        tmp_path
        / "promotion-audit.json"
    )

    result = run_cli(
        "promote",
        "--current-manifest",
        current_manifest,
        "--current-registry",
        current_registry,
        "--candidate-manifest",
        candidate_dir
        / "trusted-manifest.json",
        "--candidate-registry",
        candidate_dir
        / "trusted-policy-signers.json",
        "--backup-dir",
        backup_dir,
        "--audit-output",
        audit_path,
        "--promoted-by",
        "security-admin",
        "--plan",
        tmp_path / "promotion-plan.json",
        "--approval",
        tmp_path / "promotion-approval.json",
        "--approver-registry",
        tmp_path / "promotion-approver-registry.json",
    )

    assert result.returncode == 0
    assert audit_path.exists()

    assert (
        backup_dir
        / "trusted-manifest.before-rotation.json"
    ).exists()

    assert (
        backup_dir
        / "trusted-policy-signers.before-rotation.json"
    ).exists()

    audit = json.loads(
        audit_path.read_text(
            encoding="utf-8"
        )
    )

    assert audit["status"] == "completed"

    assert (
        audit["old_manifest_trust_basis"]
        == "historical_trust"
    )


def test_promote_reports_new_registry_fingerprint(
    tmp_path,
):
    (
        candidate_dir,
        current_manifest,
        current_registry,
    ) = prepare_promotion_state(
        tmp_path
    )

    result = run_cli(
        "promote",
        "--current-manifest",
        current_manifest,
        "--current-registry",
        current_registry,
        "--candidate-manifest",
        candidate_dir
        / "trusted-manifest.json",
        "--candidate-registry",
        candidate_dir
        / "trusted-policy-signers.json",
        "--backup-dir",
        tmp_path / "backup",
        "--audit-output",
        tmp_path / "audit.json",
        "--promoted-by",
        "security-admin",
        "--plan",
        tmp_path / "promotion-plan.json",
        "--approval",
        tmp_path / "promotion-approval.json",
        "--approver-registry",
        tmp_path / "promotion-approver-registry.json",
    )

    assert result.returncode == 0

    assert (
        "New registry SHA-256:"
        in result.stdout
    )


def test_promote_requires_trusted_approver_registry(
    tmp_path,
):
    (
        candidate_dir,
        current_manifest,
        current_registry,
    ) = prepare_promotion_state(
        tmp_path
    )

    result = run_cli(
        "promote",
        "--plan",
        tmp_path
        / "promotion-plan.json",
        "--approval",
        tmp_path
        / "promotion-approval.json",
        "--current-manifest",
        current_manifest,
        "--current-registry",
        current_registry,
        "--candidate-manifest",
        candidate_dir
        / "trusted-manifest.json",
        "--candidate-registry",
        candidate_dir
        / "trusted-policy-signers.json",
        "--backup-dir",
        tmp_path / "backup",
        "--audit-output",
        tmp_path / "audit.json",
        "--promoted-by",
        "security-admin",
    )

    assert result.returncode == 2

    assert (
        "--approver-registry"
        in result.stderr
    )

def test_promote_replaces_current_files(
    tmp_path,
):
    (
        candidate_dir,
        current_manifest,
        current_registry,
    ) = prepare_promotion_state(
        tmp_path
    )

    candidate_manifest = (
        candidate_dir
        / "trusted-manifest.json"
    )

    candidate_registry = (
        candidate_dir
        / "trusted-policy-signers.json"
    )

    result = run_cli(
        "promote",
        "--current-manifest",
        current_manifest,
        "--current-registry",
        current_registry,
        "--candidate-manifest",
        candidate_manifest,
        "--candidate-registry",
        candidate_registry,
        "--backup-dir",
        tmp_path / "backup",
        "--audit-output",
        tmp_path / "promotion-audit.json",
        "--promoted-by",
        "security-admin",
        "--promoted-at",
        "2026-10-04T11:00:00+00:00",
        "--approve",
    )

    assert result.returncode == 0

    assert (
        "Policy key rotation promoted"
        in result.stdout
    )

    assert (
        current_manifest.read_bytes()
        == candidate_manifest.read_bytes()
    )

    assert (
        current_registry.read_bytes()
        == candidate_registry.read_bytes()
    )


def test_promote_creates_audit_and_backups(
    tmp_path,
):
    (
        candidate_dir,
        current_manifest,
        current_registry,
    ) = prepare_promotion_state(
        tmp_path
    )

    backup_dir = tmp_path / "backup"

    audit_path = (
        tmp_path
        / "promotion-audit.json"
    )

    result = run_cli(
        "promote",
        "--current-manifest",
        current_manifest,
        "--current-registry",
        current_registry,
        "--candidate-manifest",
        candidate_dir
        / "trusted-manifest.json",
        "--candidate-registry",
        candidate_dir
        / "trusted-policy-signers.json",
        "--backup-dir",
        backup_dir,
        "--audit-output",
        audit_path,
        "--promoted-by",
        "security-admin",
        "--approve",
    )

    assert result.returncode == 0
    assert audit_path.exists()

    assert (
        backup_dir
        / "trusted-manifest.before-rotation.json"
    ).exists()

    assert (
        backup_dir
        / "trusted-policy-signers.before-rotation.json"
    ).exists()

    audit = json.loads(
        audit_path.read_text(
            encoding="utf-8"
        )
    )

    assert audit["status"] == "completed"

    assert (
        audit["old_manifest_trust_basis"]
        == "historical_trust"
    )


def test_promote_reports_new_registry_fingerprint(
    tmp_path,
):
    (
        candidate_dir,
        current_manifest,
        current_registry,
    ) = prepare_promotion_state(
        tmp_path
    )

    result = run_cli(
        "promote",
        "--current-manifest",
        current_manifest,
        "--current-registry",
        current_registry,
        "--candidate-manifest",
        candidate_dir
        / "trusted-manifest.json",
        "--candidate-registry",
        candidate_dir
        / "trusted-policy-signers.json",
        "--backup-dir",
        tmp_path / "backup",
        "--audit-output",
        tmp_path / "audit.json",
        "--promoted-by",
        "security-admin",
        "--approve",
    )

    assert result.returncode == 0

    assert (
        "New registry SHA-256:"
        in result.stdout
    )


def test_promote_replaces_current_files(
    tmp_path,
):
    (
        candidate_dir,
        current_manifest,
        current_registry,
    ) = prepare_promotion_state(
        tmp_path
    )

    candidate_manifest = (
        candidate_dir
        / "trusted-manifest.json"
    )

    candidate_registry = (
        candidate_dir
        / "trusted-policy-signers.json"
    )

    result = run_cli(
        "promote",
        "--current-manifest",
        current_manifest,
        "--current-registry",
        current_registry,
        "--candidate-manifest",
        candidate_manifest,
        "--candidate-registry",
        candidate_registry,
        "--backup-dir",
        tmp_path / "backup",
        "--audit-output",
        tmp_path / "promotion-audit.json",
        "--promoted-by",
        "security-admin",
        "--promoted-at",
        "2026-10-04T11:00:00+00:00",
        "--plan",
        tmp_path / "promotion-plan.json",
        "--approval",
        tmp_path / "promotion-approval.json",
        "--approver-registry",
        tmp_path / "promotion-approver-registry.json",
    )

    assert result.returncode == 0

    assert (
        "Policy key rotation promoted"
        in result.stdout
    )

    assert (
        current_manifest.read_bytes()
        == candidate_manifest.read_bytes()
    )

    assert (
        current_registry.read_bytes()
        == candidate_registry.read_bytes()
    )


def test_promote_creates_audit_and_backups(
    tmp_path,
):
    (
        candidate_dir,
        current_manifest,
        current_registry,
    ) = prepare_promotion_state(
        tmp_path
    )

    backup_dir = tmp_path / "backup"

    audit_path = (
        tmp_path
        / "promotion-audit.json"
    )

    result = run_cli(
        "promote",
        "--current-manifest",
        current_manifest,
        "--current-registry",
        current_registry,
        "--candidate-manifest",
        candidate_dir
        / "trusted-manifest.json",
        "--candidate-registry",
        candidate_dir
        / "trusted-policy-signers.json",
        "--backup-dir",
        backup_dir,
        "--audit-output",
        audit_path,
        "--promoted-by",
        "security-admin",
        "--plan",
        tmp_path / "promotion-plan.json",
        "--approval",
        tmp_path / "promotion-approval.json",
        "--approver-registry",
        tmp_path / "promotion-approver-registry.json",
    )

    assert result.returncode == 0
    assert audit_path.exists()

    assert (
        backup_dir
        / "trusted-manifest.before-rotation.json"
    ).exists()

    assert (
        backup_dir
        / "trusted-policy-signers.before-rotation.json"
    ).exists()

    audit = json.loads(
        audit_path.read_text(
            encoding="utf-8"
        )
    )

    assert audit["status"] == "completed"

    assert (
        audit["old_manifest_trust_basis"]
        == "historical_trust"
    )


def test_promote_reports_new_registry_fingerprint(
    tmp_path,
):
    (
        candidate_dir,
        current_manifest,
        current_registry,
    ) = prepare_promotion_state(
        tmp_path
    )

    result = run_cli(
        "promote",
        "--current-manifest",
        current_manifest,
        "--current-registry",
        current_registry,
        "--candidate-manifest",
        candidate_dir
        / "trusted-manifest.json",
        "--candidate-registry",
        candidate_dir
        / "trusted-policy-signers.json",
        "--backup-dir",
        tmp_path / "backup",
        "--audit-output",
        tmp_path / "audit.json",
        "--promoted-by",
        "security-admin",
        "--plan",
        tmp_path / "promotion-plan.json",
        "--approval",
        tmp_path / "promotion-approval.json",
        "--approver-registry",
        tmp_path / "promotion-approver-registry.json",
    )

    assert result.returncode == 0

    assert (
        "New registry SHA-256:"
        in result.stdout
    )


def test_cli_creates_signed_approval(
    tmp_path,
):
    result, _, plan_path, _ = (
        create_plan(tmp_path)
    )

    assert result.returncode == 0

    approver_key = (
        tmp_path
        / "approver-key.pem"
    )

    create_private_key(
        approver_key
    )

    approval_path = (
        tmp_path
        / "rotation-approval.json"
    )

    approval = run_cli(
        "approve",
        "--plan",
        plan_path,
        "--approver-private-key",
        approver_key,
        "--approved-by",
        "security-admin",
        "--approved-at",
        "2026-10-04T09:30:00+00:00",
        "--approval-id",
        "APPROVAL-CLI-001",
        "--output",
        approval_path,
    )

    assert approval.returncode == 0

    assert (
        "Signed rotation approval created"
        in approval.stdout
    )

    saved = json.loads(
        approval_path.read_text(
            encoding="utf-8"
        )
    )

    assert (
        saved["approval_id"]
        == "APPROVAL-CLI-001"
    )

    assert (
        saved["initiated_by"]
        == "security-operator"
    )

    assert (
        saved["approved_by"]
        == "security-admin"
    )

    assert "signature" in saved


def test_cli_approval_rejects_same_person(
    tmp_path,
):
    result, _, plan_path, _ = (
        create_plan(tmp_path)
    )

    assert result.returncode == 0

    approver_key = (
        tmp_path
        / "approver-key.pem"
    )

    create_private_key(
        approver_key
    )

    approval = run_cli(
        "approve",
        "--plan",
        plan_path,
        "--approver-private-key",
        approver_key,
        "--approved-by",
        "security-operator",
        "--approved-at",
        "2026-10-04T09:30:00+00:00",
        "--output",
        tmp_path / "approval.json",
    )

    assert approval.returncode == 1

    assert (
        "Separation of duties violation"
        in approval.stderr
    )
