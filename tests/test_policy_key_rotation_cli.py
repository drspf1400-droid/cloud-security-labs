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
    # Default legacy CLI tests to lab so their
    # one-approver fixtures remain valid. Tests
    # can explicitly request production.
    args = list(args)

    if (
        args
        and args[0] == "approve"
        and "--scope" not in args
    ):
        args[1:1] = [
            "--scope",
            "execute",
        ]

    if (
        args
        and args[0] in {
            "execute",
            "promote",
        }
        and "--environment" not in args
    ):
        args[1:1] = [
            "--environment",
            "lab",
        ]

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


def create_cli_role_mismatch_approvals(
    tmp_path,
    plan_path,
):
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
    )

    from modules.approver_trust_registry import (
        create_approver_registry,
        register_approver,
    )
    from modules.rotation_approval import (
        public_key_to_base64,
    )

    approvers = [
        (
            "security-admin",
            ["security-admin"],
            "role-security",
        ),
        (
            "risk-owner",
            ["risk-owner"],
            "role-risk",
        ),
    ]

    registry = create_approver_registry(
        created_at=(
            "2026-10-04T08:00:00+00:00"
        ),
        registry_id=(
            "ROLE-MISMATCH-APPROVER-REGISTRY-001"
        ),
    )

    approval_paths = []

    for index, (
        approver_id,
        roles,
        stem,
    ) in enumerate(
        approvers,
        start=1,
    ):
        private_key_path = (
            tmp_path
            / f"{stem}-private.pem"
        )

        approval_path = (
            tmp_path
            / f"{stem}-approval.json"
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

        registry = register_approver(
            registry,
            approver_id=approver_id,
            key_id=(
                f"role-approver-key-{index:03d}"
            ),
            public_key_b64=(
                public_key_to_base64(
                    private_key.public_key()
                )
            ),
            registered_at=(
                "2026-10-04T08:30:00+00:00"
            ),
            roles=roles,
        )

        approval = run_cli(
            "approve",
            "--plan",
            plan_path,
            "--approver-private-key",
            private_key_path,
            "--approved-by",
            approver_id,
            "--approved-at",
            "2026-10-04T09:30:00+00:00",
            "--approval-id",
            (
                f"ROLE-MISMATCH-APPROVAL-{index:03d}"
            ),
            "--output",
            approval_path,
        )

        assert approval.returncode == 0, (
            approval.stderr
        )

        approval_paths.append(
            approval_path
        )

    registry_path = (
        tmp_path
        / "role-mismatch-approver-registry.json"
    )

    registry_path.write_text(
        json.dumps(
            registry,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    return (
        approval_paths,
        registry_path,
    )


def create_cli_distinct_role_violation_approvals(
    tmp_path,
    plan_path,
):
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
    )

    from modules.approver_trust_registry import (
        create_approver_registry,
        register_approver,
    )

    from modules.rotation_approval import (
        public_key_to_base64,
    )

    approvers = [
        (
            "security-admin",
            [
                "security-admin",
                "platform-owner",
            ],
            "distinct-security",
        ),
        (
            "risk-owner",
            [
                "risk-owner",
            ],
            "distinct-risk",
        ),
    ]

    registry = create_approver_registry(
        created_at=(
            "2026-10-04T08:00:00+00:00"
        ),
        registry_id=(
            "DISTINCT-ROLE-REGISTRY-001"
        ),
    )

    approval_paths = []

    for index, (
        approver_id,
        roles,
        stem,
    ) in enumerate(
        approvers,
        start=1,
    ):
        private_key_path = (
            tmp_path
            / f"{stem}-private.pem"
        )

        approval_path = (
            tmp_path
            / f"{stem}-approval.json"
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

        registry = register_approver(
            registry,
            approver_id=approver_id,
            key_id=(
                f"distinct-role-key-{index:03d}"
            ),
            public_key_b64=(
                public_key_to_base64(
                    private_key.public_key()
                )
            ),
            registered_at=(
                "2026-10-04T08:30:00+00:00"
            ),
            roles=roles,
        )

        approval = run_cli(
            "approve",
            "--plan",
            plan_path,
            "--approver-private-key",
            private_key_path,
            "--approved-by",
            approver_id,
            "--approved-at",
            "2026-10-04T09:30:00+00:00",
            "--approval-id",
            (
                f"DISTINCT-ROLE-APPROVAL-{index:03d}"
            ),
            "--output",
            approval_path,
        )

        assert approval.returncode == 0, (
            approval.stderr
        )

        approval_paths.append(
            approval_path
        )

    registry_path = (
        tmp_path
        / "distinct-role-approver-registry.json"
    )

    registry_path.write_text(
        json.dumps(
            registry,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    return (
        approval_paths,
        registry_path,
    )


def create_cli_production_freshness_approvals(
    tmp_path,
    plan_path,
    approved_times,
    approval_scope="execute",
):
    from modules.approver_trust_registry import (
        create_approver_registry,
        register_approver,
    )

    from modules.policy_manifest_signing import (
        public_key_to_base64,
    )

    if len(approved_times) != 2:
        raise ValueError(
            "approved_times must contain 2 values"
        )

    approvers = [
        (
            "security-admin",
            ["security-admin"],
            "freshness-security",
        ),
        (
            "platform-owner",
            ["platform-owner"],
            "freshness-platform",
        ),
    ]

    registry = create_approver_registry(
        created_at=(
            "2026-10-04T08:00:00+00:00"
        ),
        registry_id=(
            "FRESHNESS-APPROVER-REGISTRY-001"
        ),
    )

    approval_paths = []

    for index, (
        approver_id,
        roles,
        stem,
    ) in enumerate(
        approvers,
        start=1,
    ):
        private_key_path = (
            tmp_path
            / f"{stem}-private.pem"
        )

        approval_path = (
            tmp_path
            / f"{stem}-approval.json"
        )

        private_key = create_private_key(
            private_key_path
        )

        registry = register_approver(
            registry,
            approver_id=approver_id,
            key_id=(
                f"freshness-key-{index:03d}"
            ),
            public_key_b64=(
                public_key_to_base64(
                    private_key.public_key()
                )
            ),
            registered_at=(
                "2026-10-04T08:30:00+00:00"
            ),
            roles=roles,
        )

        approval = run_cli(
            "approve",
            "--plan",
            plan_path,
            "--approver-private-key",
            private_key_path,
            "--approved-by",
            approver_id,
            "--approved-at",
            approved_times[index - 1],
            "--scope",
            approval_scope,
            "--approval-id",
            (
                f"FRESHNESS-APPROVAL-{index:03d}"
            ),
            "--output",
            approval_path,
        )

        assert approval.returncode == 0, (
            approval.stderr
        )

        approval_paths.append(
            approval_path
        )

    registry_path = (
        tmp_path
        / "freshness-approver-registry.json"
    )

    registry_path.write_text(
        json.dumps(
            registry,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )

    return (
        approval_paths,
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


def test_execute_rejects_single_approval_when_quorum_is_two(
    tmp_path,
):
    result, key_path, plan_path, _ = (
        create_plan(tmp_path)
    )

    assert result.returncode == 0

    (
        approval_path,
        approver_registry,
    ) = create_cli_signed_approval(
        tmp_path,
        plan_path,
        stem="quorum-two",
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
        approval_path,
        "--approver-registry",
        approver_registry,
        "--required-approvals",
        "2",
        "--output-dir",
        tmp_path / "candidate",
    )

    assert execute.returncode == 1

    assert (
        "quorum_not_satisfied"
        in execute.stderr
    )


def test_production_quorum_policy_cannot_be_lowered_by_cli(
    tmp_path,
):
    result, key_path, plan_path, _ = (
        create_plan(tmp_path)
    )

    assert result.returncode == 0

    (
        approval_path,
        approver_registry,
    ) = create_cli_signed_approval(
        tmp_path,
        plan_path,
        stem="production-quorum",
    )

    execute = run_cli(
        "execute",
        "--environment",
        "production",
        "--plan",
        plan_path,
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
        "--required-approvals",
        "1",
        "--output-dir",
        tmp_path / "candidate",
    )

    assert execute.returncode == 1

    assert (
        "quorum_not_satisfied"
        in execute.stderr
    )


def test_production_rejects_two_valid_approvals_with_wrong_roles(
    tmp_path,
):
    result, key_path, plan_path, _ = (
        create_plan(tmp_path)
    )

    assert result.returncode == 0

    (
        approval_paths,
        approver_registry,
    ) = create_cli_role_mismatch_approvals(
        tmp_path,
        plan_path,
    )

    execute = run_cli(
        "execute",
        "--environment",
        "production",
        "--plan",
        plan_path,
        "--manifest",
        MANIFEST,
        "--registry",
        REGISTRY,
        "--new-private-key",
        key_path,
        "--approval",
        approval_paths[0],
        "--approval",
        approval_paths[1],
        "--approver-registry",
        approver_registry,
        "--required-approvals",
        "1",
        "--output-dir",
        tmp_path / "candidate-role-mismatch",
    )

    assert execute.returncode == 1

    assert (
        "required_roles_not_satisfied"
        in execute.stderr
    )


def test_production_rejects_multi_role_approver_covering_two_roles(
    tmp_path,
):
    result, key_path, plan_path, _ = (
        create_plan(tmp_path)
    )

    assert result.returncode == 0

    (
        approval_paths,
        approver_registry,
    ) = (
        create_cli_distinct_role_violation_approvals(
            tmp_path,
            plan_path,
        )
    )

    execute = run_cli(
        "execute",
        "--environment",
        "production",
        "--plan",
        plan_path,
        "--manifest",
        MANIFEST,
        "--registry",
        REGISTRY,
        "--new-private-key",
        key_path,
        "--approval",
        approval_paths[0],
        "--approval",
        approval_paths[1],
        "--approver-registry",
        approver_registry,
        "--required-approvals",
        "1",
        "--output-dir",
        (
            tmp_path
            / "candidate-distinct-role"
        ),
    )

    assert execute.returncode == 1

    assert (
        "distinct_role_holders_not_satisfied"
        in execute.stderr
    )


def test_production_accepts_fresh_approvals(
    tmp_path,
):
    result, key_path, plan_path, _ = (
        create_plan(tmp_path)
    )

    assert result.returncode == 0

    (
        approval_paths,
        approver_registry,
    ) = create_cli_production_freshness_approvals(
        tmp_path,
        plan_path,
        [
            "2026-10-04T09:10:00+00:00",
            "2026-10-04T09:20:00+00:00",
        ],
    )

    output_dir = (
        tmp_path
        / "fresh-production-candidate"
    )

    execute = run_cli(
        "execute",
        "--environment",
        "production",
        "--plan",
        plan_path,
        "--manifest",
        MANIFEST,
        "--registry",
        REGISTRY,
        "--new-private-key",
        key_path,
        "--approval",
        approval_paths[0],
        "--approval",
        approval_paths[1],
        "--approver-registry",
        approver_registry,
        "--output-dir",
        output_dir,
    )

    assert execute.returncode == 0, (
        execute.stderr
    )

    saved = json.loads(
        (
            output_dir
            / "policy-key-rotation-result.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    assert (
        saved["policy_context"][
            "max_approval_age_seconds"
        ]
        == 3600
    )

    assert (
        saved["approval_quorum"][
            "expired_approval_count"
        ]
        == 0
    )


def test_production_rejects_expired_approval(
    tmp_path,
):
    result, key_path, plan_path, _ = (
        create_plan(tmp_path)
    )

    assert result.returncode == 0

    (
        approval_paths,
        approver_registry,
    ) = create_cli_production_freshness_approvals(
        tmp_path,
        plan_path,
        [
            "2026-10-04T08:45:00+00:00",
            "2026-10-04T09:20:00+00:00",
        ],
    )

    execute = run_cli(
        "execute",
        "--environment",
        "production",
        "--plan",
        plan_path,
        "--manifest",
        MANIFEST,
        "--registry",
        REGISTRY,
        "--new-private-key",
        key_path,
        "--approval",
        approval_paths[0],
        "--approval",
        approval_paths[1],
        "--approver-registry",
        approver_registry,
        "--output-dir",
        tmp_path
        / "expired-production-candidate",
    )

    assert execute.returncode == 1

    assert (
        "approval_freshness_not_satisfied"
        in execute.stderr
    )


def test_cli_creates_action_scoped_approval(
    tmp_path,
):
    result, _, plan_path, _ = (
        create_plan(tmp_path)
    )

    assert result.returncode == 0

    key_path = (
        tmp_path
        / "scoped-approval-key.pem"
    )

    create_private_key(
        key_path
    )

    approval_path = (
        tmp_path
        / "scoped-approval.json"
    )

    approval = run_cli(
        "approve",
        "--plan",
        plan_path,
        "--approver-private-key",
        key_path,
        "--approved-by",
        "security-admin",
        "--approved-at",
        "2026-10-04T09:30:00+00:00",
        "--scope",
        "promote",
        "--output",
        approval_path,
    )

    assert approval.returncode == 0

    saved = json.loads(
        approval_path.read_text(
            encoding="utf-8"
        )
    )

    assert (
        saved["approval_scope"]
        == "promote"
    )


def test_production_execute_rejects_promote_scoped_approvals(
    tmp_path,
):
    result, key_path, plan_path, _ = (
        create_plan(tmp_path)
    )

    assert result.returncode == 0

    (
        approval_paths,
        approver_registry,
    ) = create_cli_production_freshness_approvals(
        tmp_path,
        plan_path,
        [
            "2026-10-04T09:10:00+00:00",
            "2026-10-04T09:20:00+00:00",
        ],
        approval_scope="promote",
    )

    execute = run_cli(
        "execute",
        "--environment",
        "production",
        "--plan",
        plan_path,
        "--manifest",
        MANIFEST,
        "--registry",
        REGISTRY,
        "--new-private-key",
        key_path,
        "--approval",
        approval_paths[0],
        "--approval",
        approval_paths[1],
        "--approver-registry",
        approver_registry,
        "--output-dir",
        tmp_path / "wrong-scope-candidate",
    )

    assert execute.returncode == 1

    assert (
        "approval_scope_not_satisfied"
        in execute.stderr
    )


def test_production_promotion_requires_promote_scope(
    tmp_path,
):
    (
        candidate_dir,
        current_manifest,
        current_registry,
    ) = prepare_promotion_state(
        tmp_path
    )

    plan_path = (
        tmp_path
        / "promotion-plan.json"
    )

    (
        execute_approvals,
        execute_registry,
    ) = create_cli_production_freshness_approvals(
        tmp_path,
        plan_path,
        [
            "2026-10-04T09:40:00+00:00",
            "2026-10-04T09:50:00+00:00",
        ],
        approval_scope="execute",
    )

    rejected = run_cli(
        "promote",
        "--environment",
        "production",
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
        tmp_path / "wrong-scope-backup",
        "--audit-output",
        tmp_path / "wrong-scope-audit.json",
        "--promoted-by",
        "security-admin",
        "--promoted-at",
        "2026-10-04T10:30:00+00:00",
        "--plan",
        plan_path,
        "--approval",
        execute_approvals[0],
        "--approval",
        execute_approvals[1],
        "--approver-registry",
        execute_registry,
    )

    assert rejected.returncode == 1

    assert (
        "approval_scope_not_satisfied"
        in rejected.stderr
    )

    (
        promote_approvals,
        promote_registry,
    ) = create_cli_production_freshness_approvals(
        tmp_path,
        plan_path,
        [
            "2026-10-04T09:40:00+00:00",
            "2026-10-04T09:50:00+00:00",
        ],
        approval_scope="promote",
    )

    accepted = run_cli(
        "promote",
        "--environment",
        "production",
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
        tmp_path / "correct-scope-backup",
        "--audit-output",
        tmp_path / "correct-scope-audit.json",
        "--promoted-by",
        "security-admin",
        "--promoted-at",
        "2026-10-04T10:30:00+00:00",
        "--plan",
        plan_path,
        "--approval",
        promote_approvals[0],
        "--approval",
        promote_approvals[1],
        "--approver-registry",
        promote_registry,
    )

    assert accepted.returncode == 0, (
        accepted.stderr
    )
