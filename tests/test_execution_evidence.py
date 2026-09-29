import importlib.util
from copy import deepcopy
from pathlib import Path


MODULE_PATH = Path(
    "modules/execution_evidence.py"
)

spec = importlib.util.spec_from_file_location(
    "execution_evidence",
    MODULE_PATH,
)

evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


def sample_execution_result():
    return {
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
                                "remediation_applied",
                        },
                        {
                            "action":
                                "verification_passed",
                        },
                    ],
                }
            ]
        },
    }


def test_manifest_contains_run_metadata():
    result = evidence.build_execution_evidence(
        sample_execution_result(),
        actor="tester",
        run_id="RUN-001",
        timestamp="2026-09-29T10:00:00+00:00",
    )

    assert result["manifest_version"] == "1.0"
    assert result["run_id"] == "RUN-001"
    assert result["actor"] == "tester"
    assert result["environment"] == "lab"

    assert result["summary"]["executed"] == 1


def test_executed_finding_contains_verification_evidence():
    result = evidence.build_execution_evidence(
        sample_execution_result(),
        actor="tester",
        run_id="RUN-001",
    )

    item = result["evidence"][0]

    assert item["finding_id"] == "SSH-002"
    assert item["execution_status"] == "executed"
    assert item["remediation_applied"] is True
    assert item["verification_passed"] is True
    assert item["verification_failed"] is False
    assert item["rollback_performed"] is False


def test_rollback_evidence_is_preserved():
    source = sample_execution_result()

    source["summary"] = {
        "executed": 0,
        "dry_run": 0,
        "blocked": 0,
        "failed": 1,
    }

    source["results"][0]["status"] = "failed"
    source["results"][0]["reason"] = (
        "Remediation verification failed; "
        "rollback completed"
    )

    finding = source["assessment"]["findings"][0]

    finding["status"] = "approved"

    finding["remediation"] = {
        "applied": False,
        "rollback_performed": True,
        "rollback_verified": True,
    }

    finding["audit_trail"] = [
        {"action": "remediation_applied"},
        {"action": "verification_failed"},
        {"action": "rollback_started"},
        {"action": "rollback_completed"},
    ]

    result = evidence.build_execution_evidence(
        source,
        actor="tester",
        run_id="RUN-ROLLBACK",
    )

    item = result["evidence"][0]

    assert item["execution_status"] == "failed"
    assert item["verification_failed"] is True
    assert item["rollback_performed"] is True
    assert item["rollback_verified"] is True
    assert "rollback_completed" in (
        item["finding_audit_events"]
    )


def test_manifest_does_not_mutate_execution_result():
    source = sample_execution_result()
    original = deepcopy(source)

    evidence.build_execution_evidence(
        source,
        actor="tester",
        run_id="RUN-001",
    )

    assert source == original


def test_manifest_integrity_verifies():
    manifest = evidence.build_execution_evidence(
        sample_execution_result(),
        actor="tester",
        run_id="RUN-001",
    )

    assert (
        evidence.verify_manifest_integrity(
            manifest
        )
        is True
    )


def test_manifest_integrity_detects_tampering():
    manifest = evidence.build_execution_evidence(
        sample_execution_result(),
        actor="tester",
        run_id="RUN-001",
    )

    manifest["summary"]["executed"] = 999

    assert (
        evidence.verify_manifest_integrity(
            manifest
        )
        is False
    )
