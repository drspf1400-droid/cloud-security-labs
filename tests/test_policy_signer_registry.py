import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from modules.policy_manifest_signing import (
    public_key_fingerprint,
    public_key_to_base64,
)

from modules.policy_signer_registry import (
    PolicySignerRegistryError,
    create_policy_signer_registry,
    get_policy_signer,
    policy_signer_lifecycle,
    register_policy_signer,
    revoke_policy_signer,
    rotate_policy_signer,
)


def new_key():
    private_key = (
        Ed25519PrivateKey.generate()
    )

    public_key = (
        private_key.public_key()
    )

    return {
        "private": private_key,
        "public_b64": (
            public_key_to_base64(
                public_key
            )
        ),
        "fingerprint": (
            public_key_fingerprint(
                public_key
            )
        ),
    }


def base_registry():
    return create_policy_signer_registry(
        registry_id="POLICY-SIGNERS-001",
        created_at=(
            "2026-10-03T10:00:00+00:00"
        ),
    )


def test_registry_can_register_signer():
    key = new_key()

    registry = register_policy_signer(
        base_registry(),
        signer_id=(
            "security-policy-authority"
        ),
        key_id="policy-key-001",
        public_key_b64=key["public_b64"],
        registered_at=(
            "2026-10-03T11:00:00+00:00"
        ),
    )

    signer = get_policy_signer(
        registry,
        key["fingerprint"],
    )

    assert signer["status"] == "active"

    assert (
        signer["key_id"]
        == "policy-key-001"
    )


def test_duplicate_key_is_rejected():
    key = new_key()

    registry = register_policy_signer(
        base_registry(),
        signer_id="authority",
        key_id="key-001",
        public_key_b64=key["public_b64"],
        registered_at=(
            "2026-10-03T11:00:00+00:00"
        ),
    )

    with pytest.raises(
        PolicySignerRegistryError
    ):
        register_policy_signer(
            registry,
            signer_id="authority",
            key_id="key-002",
            public_key_b64=(
                key["public_b64"]
            ),
            registered_at=(
                "2026-10-03T12:00:00+00:00"
            ),
        )


def test_signer_can_be_revoked():
    key = new_key()

    registry = register_policy_signer(
        base_registry(),
        signer_id="authority",
        key_id="key-001",
        public_key_b64=key["public_b64"],
        registered_at=(
            "2026-10-03T11:00:00+00:00"
        ),
    )

    registry = revoke_policy_signer(
        registry,
        key["fingerprint"],
        revoked_at=(
            "2026-10-03T12:00:00+00:00"
        ),
        reason="key_compromise",
    )

    signer = get_policy_signer(
        registry,
        key["fingerprint"],
    )

    assert signer["status"] == "revoked"

    assert (
        signer["revocation_reason"]
        == "key_compromise"
    )


def test_revocation_before_registration_is_rejected():
    key = new_key()

    registry = register_policy_signer(
        base_registry(),
        signer_id="authority",
        key_id="key-001",
        public_key_b64=key["public_b64"],
        registered_at=(
            "2026-10-03T12:00:00+00:00"
        ),
    )

    with pytest.raises(
        PolicySignerRegistryError
    ):
        revoke_policy_signer(
            registry,
            key["fingerprint"],
            revoked_at=(
                "2026-10-03T11:00:00+00:00"
            ),
            reason="invalid-test",
        )


def test_rotation_revokes_old_and_activates_new():
    old_key = new_key()
    new_signing_key = new_key()

    registry = register_policy_signer(
        base_registry(),
        signer_id="authority",
        key_id="key-001",
        public_key_b64=(
            old_key["public_b64"]
        ),
        registered_at=(
            "2026-10-03T11:00:00+00:00"
        ),
    )

    registry = rotate_policy_signer(
        registry,
        old_key["fingerprint"],
        new_signer_id="authority",
        new_key_id="key-002",
        new_public_key_b64=(
            new_signing_key[
                "public_b64"
            ]
        ),
        rotated_at=(
            "2026-10-03T13:00:00+00:00"
        ),
    )

    old_signer = get_policy_signer(
        registry,
        old_key["fingerprint"],
    )

    new_signer = get_policy_signer(
        registry,
        new_signing_key[
            "fingerprint"
        ],
    )

    assert old_signer["status"] == "revoked"
    assert new_signer["status"] == "active"

    assert (
        new_signer["key_id"]
        == "key-002"
    )


def test_rotation_creates_audit_events():
    old_key = new_key()
    new_signing_key = new_key()

    registry = register_policy_signer(
        base_registry(),
        signer_id="authority",
        key_id="key-001",
        public_key_b64=(
            old_key["public_b64"]
        ),
        registered_at=(
            "2026-10-03T11:00:00+00:00"
        ),
    )

    registry = rotate_policy_signer(
        registry,
        old_key["fingerprint"],
        new_signer_id="authority",
        new_key_id="key-002",
        new_public_key_b64=(
            new_signing_key[
                "public_b64"
            ]
        ),
        rotated_at=(
            "2026-10-03T13:00:00+00:00"
        ),
    )

    actions = [
        event["action"]
        for event in registry[
            "audit_trail"
        ]
    ]

    assert "register" in actions
    assert "revoke" in actions
    assert "rotate" in actions


def test_lifecycle_contains_related_events():
    old_key = new_key()
    new_signing_key = new_key()

    registry = register_policy_signer(
        base_registry(),
        signer_id="authority",
        key_id="key-001",
        public_key_b64=(
            old_key["public_b64"]
        ),
        registered_at=(
            "2026-10-03T11:00:00+00:00"
        ),
    )

    registry = rotate_policy_signer(
        registry,
        old_key["fingerprint"],
        new_signer_id="authority",
        new_key_id="key-002",
        new_public_key_b64=(
            new_signing_key[
                "public_b64"
            ]
        ),
        rotated_at=(
            "2026-10-03T13:00:00+00:00"
        ),
    )

    lifecycle = policy_signer_lifecycle(
        registry,
        old_key["fingerprint"],
    )

    actions = {
        event["action"]
        for event in lifecycle[
            "audit_events"
        ]
    }

    assert lifecycle["signer"][
        "status"
    ] == "revoked"

    assert "register" in actions
    assert "revoke" in actions
    assert "rotate" in actions


def test_registry_operations_do_not_mutate_input():
    key = new_key()

    original = base_registry()

    result = register_policy_signer(
        original,
        signer_id="authority",
        key_id="key-001",
        public_key_b64=key["public_b64"],
        registered_at=(
            "2026-10-03T11:00:00+00:00"
        ),
    )

    assert original["signers"] == []
    assert original["audit_trail"] == []

    assert len(result["signers"]) == 1


def signed_manifest(
    key,
    *,
    created_at,
    signer_id="authority",
    key_id="key-001",
):
    from modules.policy_manifest_signing import (
        sign_policy_manifest,
    )

    manifest = {
        "manifest_version": "1.0",
        "manifest_id": "MANIFEST-TRUST-001",
        "created_at": created_at,
        "algorithm": "sha256",
        "policies": {},
    }

    return sign_policy_manifest(
        manifest,
        key["private"],
        signer_id=signer_id,
        key_id=key_id,
    )


def registered_registry(
    key,
    *,
    registered_at=(
        "2026-10-03T10:00:00+00:00"
    ),
):
    return register_policy_signer(
        base_registry(),
        signer_id="authority",
        key_id="key-001",
        public_key_b64=key["public_b64"],
        registered_at=registered_at,
    )


def test_active_signer_has_current_trust():
    from modules.policy_signer_registry import (
        evaluate_policy_manifest_trust,
    )

    key = new_key()

    registry = registered_registry(key)

    manifest = signed_manifest(
        key,
        created_at=(
            "2026-10-03T11:00:00+00:00"
        ),
    )

    result = evaluate_policy_manifest_trust(
        manifest,
        registry,
    )

    assert (
        result["current_trust"]["accepted"]
        is True
    )

    assert (
        result["effective_trust"]["basis"]
        == "current_trust"
    )


def test_revoked_signer_can_be_historically_trusted():
    from modules.policy_signer_registry import (
        evaluate_policy_manifest_trust,
    )

    key = new_key()

    registry = registered_registry(key)

    manifest = signed_manifest(
        key,
        created_at=(
            "2026-10-03T11:00:00+00:00"
        ),
    )

    registry = revoke_policy_signer(
        registry,
        key["fingerprint"],
        revoked_at=(
            "2026-10-03T12:00:00+00:00"
        ),
        reason="rotation",
    )

    result = evaluate_policy_manifest_trust(
        manifest,
        registry,
    )

    assert (
        result["current_trust"]["accepted"]
        is False
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


def test_manifest_after_revocation_is_rejected():
    from modules.policy_signer_registry import (
        evaluate_policy_manifest_trust,
    )

    key = new_key()

    registry = registered_registry(key)

    registry = revoke_policy_signer(
        registry,
        key["fingerprint"],
        revoked_at=(
            "2026-10-03T12:00:00+00:00"
        ),
        reason="rotation",
    )

    manifest = signed_manifest(
        key,
        created_at=(
            "2026-10-03T13:00:00+00:00"
        ),
    )

    result = evaluate_policy_manifest_trust(
        manifest,
        registry,
    )

    assert (
        result["effective_trust"]["accepted"]
        is False
    )

    assert (
        result["historical_trust"]["status"]
        == "after_revocation"
    )


def test_manifest_before_registration_is_rejected():
    from modules.policy_signer_registry import (
        evaluate_policy_manifest_trust,
    )

    key = new_key()

    registry = registered_registry(
        key,
        registered_at=(
            "2026-10-03T12:00:00+00:00"
        ),
    )

    manifest = signed_manifest(
        key,
        created_at=(
            "2026-10-03T11:00:00+00:00"
        ),
    )

    result = evaluate_policy_manifest_trust(
        manifest,
        registry,
    )

    assert (
        result["historical_trust"]["accepted"]
        is False
    )

    assert (
        result["historical_trust"]["status"]
        == "before_registration"
    )


def test_unknown_manifest_signer_is_rejected():
    from modules.policy_signer_registry import (
        evaluate_policy_manifest_trust,
    )

    registered_key = new_key()
    unknown_key = new_key()

    registry = registered_registry(
        registered_key
    )

    manifest = signed_manifest(
        unknown_key,
        created_at=(
            "2026-10-03T11:00:00+00:00"
        ),
    )

    result = evaluate_policy_manifest_trust(
        manifest,
        registry,
    )

    assert (
        result["effective_trust"]["accepted"]
        is False
    )

    assert (
        result["current_trust"]["status"]
        == "unknown_signer"
    )


def test_manifest_signer_metadata_mismatch_is_rejected():
    from modules.policy_signer_registry import (
        evaluate_policy_manifest_trust,
    )

    key = new_key()

    registry = registered_registry(key)

    manifest = signed_manifest(
        key,
        created_at=(
            "2026-10-03T11:00:00+00:00"
        ),
    )

    manifest["signature"][
        "signer_id"
    ] = "attacker"

    result = evaluate_policy_manifest_trust(
        manifest,
        registry,
    )

    assert (
        result["effective_trust"]["accepted"]
        is False
    )

    assert (
        result["current_trust"]["status"]
        == "signer_metadata_mismatch"
    )


def test_tampered_manifest_is_rejected_by_registry():
    from modules.policy_signer_registry import (
        evaluate_policy_manifest_trust,
    )

    key = new_key()

    registry = registered_registry(key)

    manifest = signed_manifest(
        key,
        created_at=(
            "2026-10-03T11:00:00+00:00"
        ),
    )

    manifest["manifest_id"] = (
        "TAMPERED-MANIFEST"
    )

    result = evaluate_policy_manifest_trust(
        manifest,
        registry,
    )

    assert (
        result["effective_trust"]["accepted"]
        is False
    )

    assert (
        result["current_trust"]["status"]
        == "invalid_signature"
    )


def test_trust_evaluation_contains_lifecycle():
    from modules.policy_signer_registry import (
        evaluate_policy_manifest_trust,
    )

    key = new_key()

    registry = registered_registry(key)

    manifest = signed_manifest(
        key,
        created_at=(
            "2026-10-03T11:00:00+00:00"
        ),
    )

    result = evaluate_policy_manifest_trust(
        manifest,
        registry,
    )

    assert (
        result["signer_lifecycle"]
        ["signer"]["key_id"]
        == "key-001"
    )

    assert (
        len(
            result["signer_lifecycle"]
            ["audit_events"]
        )
        >= 1
    )


def test_committed_policy_signer_registry_trusts_current_manifest():
    import json
    from pathlib import Path

    from modules.policy_signer_registry import (
        evaluate_policy_manifest_trust,
    )

    root = Path(__file__).resolve().parents[1]

    policy_dir = (
        root
        / "policies"
        / "security-gates"
    )

    manifest = json.loads(
        (
            policy_dir
            / "trusted-manifest.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    registry = json.loads(
        (
            policy_dir
            / "trusted-policy-signers.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    result = evaluate_policy_manifest_trust(
        manifest,
        registry,
    )

    assert (
        result["effective_trust"]["accepted"]
        is True
    )

    assert (
        result["effective_trust"]["basis"]
        == "current_trust"
    )

    assert (
        result["current_trust"]["status"]
        == "trusted"
    )


def test_committed_registry_matches_manifest_signer():
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]

    policy_dir = (
        root
        / "policies"
        / "security-gates"
    )

    manifest = json.loads(
        (
            policy_dir
            / "trusted-manifest.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    registry = json.loads(
        (
            policy_dir
            / "trusted-policy-signers.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    signature = manifest["signature"]

    signer = next(
        item
        for item in registry["signers"]
        if (
            item["key_fingerprint"]
            == signature["key_fingerprint"]
        )
    )

    assert (
        signer["signer_id"]
        == signature["signer_id"]
    )

    assert (
        signer["key_id"]
        == signature["key_id"]
    )

    assert signer["status"] == "active"


def test_committed_registry_contains_no_private_key():
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]

    registry = json.loads(
        (
            root
            / "policies"
            / "security-gates"
            / "trusted-policy-signers.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    serialized = json.dumps(
        registry
    ).lower()

    assert "private_key" not in serialized
    assert "private key" not in serialized


def test_registry_fingerprint_is_stable():
    import json
    from pathlib import Path

    from modules.policy_signer_registry import (
        policy_signer_registry_fingerprint,
    )

    root = Path(__file__).resolve().parents[1]

    registry = json.loads(
        (
            root
            / "policies"
            / "security-gates"
            / "trusted-policy-signers.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    assert (
        policy_signer_registry_fingerprint(
            registry
        )
        == policy_signer_registry_fingerprint(
            registry
        )
    )


def test_registry_change_changes_fingerprint():
    import json
    from copy import deepcopy
    from pathlib import Path

    from modules.policy_signer_registry import (
        policy_signer_registry_fingerprint,
    )

    root = Path(__file__).resolve().parents[1]

    registry = json.loads(
        (
            root
            / "policies"
            / "security-gates"
            / "trusted-policy-signers.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    modified = deepcopy(registry)

    modified["signers"][0][
        "status"
    ] = "revoked"

    assert (
        policy_signer_registry_fingerprint(
            registry
        )
        != policy_signer_registry_fingerprint(
            modified
        )
    )
