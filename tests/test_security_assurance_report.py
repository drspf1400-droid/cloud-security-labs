import json
from copy import deepcopy

from modules.security_assurance_report import (
    build_security_assurance_report,
    render_security_assurance_html,
)


def sample_assessment():
    return {
        "assessment": {
            "assessment_id": "ASM-001",
            "score": 70,
            "risk_level": "high",
            "remediation_policy": {
                "environment": "lab",
                "summary": {
                    "apply": 1,
                    "dry_run": 0,
                    "blocked": 1,
                },
            },
            "execution_plan": {
                "environment": "lab",
                "summary": {
                    "apply": 1,
                    "dry_run": 0,
                    "blocked": 1,
                },
                "items": [],
            },
            "execution": {
                "environment": "lab",
                "summary": {
                    "executed": 1,
                    "dry_run": 0,
                    "blocked": 1,
                    "failed": 0,
                },
                "results": [],
                "audit_trail": [],
            },
            "execution_evidence": {
                "integrity": {
                    "algorithm": "sha256",
                    "sha256": "a" * 64,
                },
                "provenance": {
                    "algorithm": "ed25519",
                    "key_fingerprint": "b" * 64,
                    "signature": "signature",
                },
            },
        },
        "asset": {
            "asset_id": "LAB-001",
            "hostname": "ubuntu-lab",
            "asset_type": "linux_server",
            "environment": "lab",
        },
        "findings": [
            {
                "finding_id": "SSH-002",
                "title": "SSH root login enabled",
                "category": "ssh",
                "baseline_severity": "high",
                "status": "remediated",
                "remediation": {
                    "recommendation":
                        "Disable direct SSH root login.",
                    "approval_status": "approved",
                    "applied": True,
                },
            },
            {
                "finding_id": "UNKNOWN-001",
                "title": "Unsupported finding",
                "category": "unknown",
                "baseline_severity": "critical",
                "status": "open",
                "remediation": {
                    "recommendation":
                        "Review manually.",
                    "approval_status": "pending",
                    "applied": False,
                },
            },
        ],
    }


def sample_trust_report():
    return {
        "signer": {
            "signer_id": "security-automation",
            "key_id": "key-1",
            "key_status": "active",
        },
        "verification": {
            "signature_valid": True,
            "effective_decision": "accept",
            "decision_basis": "current_trust",
        },
    }


def test_report_builds_executive_summary():
    report = build_security_assurance_report(
        sample_assessment(),
        sample_trust_report(),
        report_id="ASSURANCE-001",
        generated_at="2026-09-30T10:00:00+00:00",
    )

    summary = report["executive_summary"]

    assert summary["assessment_id"] == "ASM-001"
    assert summary["security_score"] == 70
    assert summary["risk_level"] == "high"
    assert summary["total_findings"] == 2
    assert summary["critical_findings"] == 1
    assert summary["high_findings"] == 1


def test_verified_report_has_verified_assurance_state():
    assessment = sample_assessment()

    assessment["findings"][1][
        "baseline_severity"
    ] = "medium"

    assessment["findings"][1][
        "status"
    ] = "false_positive"

    assessment["assessment"]["execution"][
        "summary"
    ]["blocked"] = 0

    report = build_security_assurance_report(
        assessment,
        sample_trust_report(),
    )

    assert (
        report["executive_summary"]
        ["assurance_state"]
        == "verified"
    )


def test_rejected_trust_requires_attention():
    trust = sample_trust_report()

    trust["verification"][
        "effective_decision"
    ] = "reject"

    report = build_security_assurance_report(
        sample_assessment(),
        trust,
    )

    assert (
        report["executive_summary"]
        ["assurance_state"]
        == "attention_required"
    )


def test_failed_execution_requires_attention():
    assessment = sample_assessment()

    assessment["assessment"]["execution"][
        "summary"
    ]["failed"] = 1

    report = build_security_assurance_report(
        assessment,
        sample_trust_report(),
    )

    assert (
        report["executive_summary"]
        ["assurance_state"]
        == "attention_required"
    )


def test_report_does_not_mutate_inputs():
    assessment = sample_assessment()
    trust = sample_trust_report()

    original_assessment = deepcopy(
        assessment
    )
    original_trust = deepcopy(trust)

    build_security_assurance_report(
        assessment,
        trust,
    )

    assert assessment == original_assessment
    assert trust == original_trust


def test_report_is_json_serializable():
    report = build_security_assurance_report(
        sample_assessment(),
        sample_trust_report(),
    )

    serialized = json.dumps(report)
    restored = json.loads(serialized)

    assert restored == report


def test_html_contains_professional_sections():
    report = build_security_assurance_report(
        sample_assessment(),
        sample_trust_report(),
    )

    html = render_security_assurance_html(
        report
    )

    assert "Security Assurance Report" in html
    assert "Executive Summary" in html
    assert "Asset Context" in html
    assert "Assurance Controls" in html
    assert "Trust Assurance" in html
    assert "Security Findings" in html


def test_html_escapes_untrusted_finding_text():
    assessment = sample_assessment()

    assessment["findings"][0]["title"] = (
        "<script>alert(1)</script>"
    )

    report = build_security_assurance_report(
        assessment,
        sample_trust_report(),
    )

    html = render_security_assurance_html(
        report
    )

    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_security_assurance_report_matches_schema():
    from pathlib import Path
    from jsonschema import validate

    report = build_security_assurance_report(
        sample_assessment(),
        sample_trust_report(),
        report_id="ASSURANCE-SCHEMA-001",
        generated_at="2026-09-30T10:00:00+00:00",
    )

    schema = json.loads(
        Path(
            "schemas/security-assurance-report-schema.json"
        ).read_text()
    )

    validate(
        instance=report,
        schema=schema,
    )


def test_report_writer_creates_json_and_html(tmp_path):
    from modules.security_assurance_report import (
        write_security_assurance_report,
    )

    report = build_security_assurance_report(
        sample_assessment(),
        sample_trust_report(),
        report_id="ASSURANCE-WRITE-001",
        generated_at="2026-09-30T10:00:00+00:00",
    )

    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"

    write_security_assurance_report(
        report,
        json_path=json_path,
        html_path=html_path,
    )

    assert json_path.exists()
    assert html_path.exists()

    saved = json.loads(
        json_path.read_text()
    )

    assert saved == report

    html = html_path.read_text()

    assert "Security Assurance Report" in html
    assert "ASSURANCE-WRITE-001" in html


def test_unresolved_severe_finding_requires_attention():
    report = build_security_assurance_report(
        sample_assessment(),
        sample_trust_report(),
    )

    assert (
        report["executive_summary"]
        ["assurance_state"]
        == "attention_required"
    )
