from copy import deepcopy

import pytest

from modules.ai_analysis import (
    analyze_assessment,
    build_analysis_request,
)


def sample_assessment():
    return {
        "schema_version": "1.0",
        "assessment": {
            "assessment_id": "AI-TEST-001",
            "scanner": {
                "name": "test-scanner",
                "version": "1.0",
            },
            "score": 60,
            "risk_level": "high",
        },
        "asset": {
            "asset_id": "ASSET-001",
            "hostname": "test-host",
            "asset_type": "linux_server",
            "environment": "lab",
            "internet_exposed": False,
            "business_criticality": "medium",
        },
        "findings": [
            {
                "finding_id": "SSH-002",
                "category": "ssh",
                "title": "SSH root login permitted",
                "baseline_severity": "high",
                "status": "open",
                "source": {
                    "type": "linux_configuration",
                    "module": "ssh_check",
                },
                "evidence": {
                    "type": "configuration",
                    "source": "/etc/ssh/sshd_config",
                    "key": "PermitRootLogin",
                    "observed_value": "yes",
                },
                "classification": {
                    "cve": None,
                    "cwe": None,
                    "cvss": None,
                },
                "remediation": {
                    "recommendation":
                        "Disable direct SSH root login.",
                    "approval_status": "pending",
                    "applied": False,
                },
                "verification": {
                    "security": "not_tested",
                    "configuration": "not_tested",
                    "functionality": "not_tested",
                },
                "priority": {
                    "score": 5,
                    "reasons": [
                        "baseline_severity=high",
                        "ssh_root_login_permitted=true",
                    ],
                    "engine": {
                        "name":
                            "deterministic-context-baseline",
                        "version": "2.0",
                    },
                },
            }
        ],
    }


def valid_analyzer(_request):
    return {
        "risk_summary":
            "Direct SSH root login increases administrative risk.",
        "evidence_interpretation": [
            "PermitRootLogin is explicitly enabled."
        ],
        "recommended_action":
            "Disable direct root login after human review.",
        "confidence": 0.92,
        "confidence_basis": [
            "Configuration evidence is explicit."
        ],
        "priority_recommendation": "keep",
        "evidence_refs": [
            "finding.evidence",
            "finding.baseline_severity",
            "finding.priority",
        ],
        "limitations": [
            "No external network reachability evidence was supplied."
        ],
    }


def test_ai_analysis_is_advisory_only():
    assessment = sample_assessment()

    report = analyze_assessment(
        assessment,
        valid_analyzer,
        provider_name="test-provider",
        model_name="test-model",
    )

    assert report["advisory_only"] is True

    analysis = report["analyses"][0]

    assert analysis["requires_human_review"] is True
    assert analysis["execution_authorized"] is False
    assert len(analysis["input_sha256"]) == 64
    assert len(
        report["source_assessment_sha256"]
    ) == 64


def test_ai_analysis_does_not_mutate_assessment():
    assessment = sample_assessment()
    original = deepcopy(assessment)

    analyze_assessment(
        assessment,
        valid_analyzer,
        provider_name="test-provider",
        model_name="test-model",
    )

    assert assessment == original


def test_ai_cannot_inject_execution_authorization():
    def unsafe_analyzer(_request):
        output = valid_analyzer(_request)
        output["execution_authorized"] = True
        return output

    with pytest.raises(
        ValueError,
        match="unsupported fields",
    ):
        analyze_assessment(
            sample_assessment(),
            unsafe_analyzer,
            provider_name="unsafe-provider",
            model_name="unsafe-model",
        )


def test_ai_cannot_reference_unavailable_evidence():
    def hallucinating_analyzer(_request):
        output = valid_analyzer(_request)
        output["evidence_refs"] = [
            "finding.evidence",
            "internet.external-threat-feed",
        ]
        return output

    with pytest.raises(
        ValueError,
        match="unavailable evidence",
    ):
        analyze_assessment(
            sample_assessment(),
            hallucinating_analyzer,
            provider_name="test-provider",
            model_name="test-model",
        )


def test_request_excludes_control_fields():
    assessment = sample_assessment()
    finding = assessment["findings"][0]

    request = build_analysis_request(
        finding,
        assessment["asset"],
    )

    assert "status" not in request["finding"]
    assert "remediation" not in request["finding"]
    assert "human_review" not in request["finding"]

    assert (
        request["guardrails"][
            "execution_authorized"
        ]
        is False
    )

    assert (
        request["guardrails"][
            "human_review_required"
        ]
        is True
    )
