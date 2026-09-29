import importlib.util
from copy import deepcopy
from pathlib import Path


EVIDENCE_PATH = Path(
    "modules/execution_evidence.py"
)

SIGNING_PATH = Path(
    "modules/evidence_signing.py"
)


spec = importlib.util.spec_from_file_location(
    "execution_evidence",
    EVIDENCE_PATH,
)
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


spec = importlib.util.spec_from_file_location(
    "evidence_signing",
    SIGNING_PATH,
)
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)


def sample_manifest():
    execution_result = {
        "environment": "lab",
        "summary": {
            "executed": 1,
            "dry_run": 0,
            "blocked": 0,
            "failed": 0,
        },
        "results": [
            {
                "finding_id": "SSH-002",
                "decision": "apply",
                "action": "disable_ssh_root_login",
                "status": "executed",
                "reason": (
                    "Remediation executed and verified."
                ),
            }
        ],
        "assessment": {
            "findings": [
                {
                    "finding_id": "SSH-002",
                    "status": "remediated",
                    "remediation": {
                        "applied": True,
                        "rollback_performed": False,
                        "rollback_verified": False,
                    },
                    "audit_trail": [
                        {
                            "action":
                                "remediation_applied"
                        },
                        {
                            "action":
                                "verification_passed"
                        },
                    ],
                }
            ]
        },
    }

    return evidence.build_execution_evidence(
        execution_result,
        actor="tester",
        run_id="RUN-SIGNED-001",
        timestamp="2026-09-29T10:00:00+00:00",
    )


def test_keypair_can_be_generated():
    private_key, public_key = (
        signing.generate_ed25519_keypair()
    )

    assert private_key is not None
    assert public_key is not None


def test_manifest_can_be_signed_and_verified():
    private_key, public_key = (
        signing.generate_ed25519_keypair()
    )

    manifest = sample_manifest()

    signed = signing.sign_execution_manifest(
        manifest,
        private_key,
    )

    assert signed["provenance"][
        "algorithm"
    ] == "ed25519"

    assert signing.verify_signed_manifest(
        signed,
        public_key,
    )


def test_signing_does_not_mutate_original_manifest():
    private_key, _ = (
        signing.generate_ed25519_keypair()
    )

    manifest = sample_manifest()
    original = deepcopy(manifest)

    signing.sign_execution_manifest(
        manifest,
        private_key,
    )

    assert manifest == original


def test_wrong_public_key_is_rejected():
    private_key, _ = (
        signing.generate_ed25519_keypair()
    )

    _, wrong_public_key = (
        signing.generate_ed25519_keypair()
    )

    signed = signing.sign_execution_manifest(
        sample_manifest(),
        private_key,
    )

    assert (
        signing.verify_signed_manifest(
            signed,
            wrong_public_key,
        )
        is False
    )


def test_manifest_tampering_is_rejected():
    private_key, public_key = (
        signing.generate_ed25519_keypair()
    )

    signed = signing.sign_execution_manifest(
        sample_manifest(),
        private_key,
    )

    signed["summary"]["executed"] = 999

    assert (
        signing.verify_signed_manifest(
            signed,
            public_key,
        )
        is False
    )


def test_signature_tampering_is_rejected():
    private_key, public_key = (
        signing.generate_ed25519_keypair()
    )

    signed = signing.sign_execution_manifest(
        sample_manifest(),
        private_key,
    )

    signed["provenance"]["signature"] = (
        "AAAAAAAAAAAAAAAA"
    )

    assert (
        signing.verify_signed_manifest(
            signed,
            public_key,
        )
        is False
    )


def test_fingerprint_changes_for_different_keys():
    _, public_key_a = (
        signing.generate_ed25519_keypair()
    )

    _, public_key_b = (
        signing.generate_ed25519_keypair()
    )

    assert (
        signing.public_key_fingerprint(
            public_key_a
        )
        != signing.public_key_fingerprint(
            public_key_b
        )
    )


def test_signed_execution_evidence_matches_schema():
    import json

    from jsonschema import validate
    from modules.execution_engine import (
        execute_assessment_plan,
    )

    schema = json.loads(
        Path(
            "schemas/finding-schema.json"
        ).read_text()
    )

    assessment = json.loads(
        Path(
            "schemas/finding-example.json"
        ).read_text()
    )

    private_key, _ = (
        signing.generate_ed25519_keypair()
    )

    result = execute_assessment_plan(
        assessment,
        actor="schema-test",
        execution_context={},
        run_id="RUN-SCHEMA-SIGNED-001",
        evidence_timestamp=(
            "2026-09-29T10:00:00+00:00"
        ),
        signing_private_key=private_key,
    )

    validate(
        instance=result["assessment"],
        schema=schema,
    )
