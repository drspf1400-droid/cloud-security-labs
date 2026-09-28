import importlib.util
from pathlib import Path


MODULE_PATH = Path("modules/prioritize.py")
spec = importlib.util.spec_from_file_location("prioritize", MODULE_PATH)
prioritize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prioritize)


def test_unknown_context_uses_baseline_only():
    finding = {
        "finding_id": "TEST-001",
        "baseline_severity": "high",
    }

    asset = {
        "internet_exposed": None,
        "business_criticality": "unknown",
        "environment": "unknown",
    }

    result = prioritize.prioritize_finding(finding, asset)

    assert result["score"] == 4
    assert result["reasons"] == [
        "baseline_severity=high"
    ]
    assert result["engine"]["name"] == "deterministic-baseline"
    assert result["engine"]["version"] == "1.0"


def test_known_context_adds_modifiers():
    finding = {
        "finding_id": "TEST-002",
        "baseline_severity": "medium",
    }

    asset = {
        "internet_exposed": True,
        "business_criticality": "critical",
        "environment": "production",
    }

    result = prioritize.prioritize_finding(finding, asset)

    assert result["score"] == 6
    assert "internet_exposed=true" in result["reasons"]
    assert "business_criticality=critical" in result["reasons"]
    assert "environment=production" in result["reasons"]


def test_false_exposure_does_not_add_score():
    finding = {
        "finding_id": "TEST-003",
        "baseline_severity": "medium",
    }

    asset = {
        "internet_exposed": False,
        "business_criticality": "low",
        "environment": "development",
    }

    result = prioritize.prioritize_finding(finding, asset)

    assert result["score"] == 3


def test_prioritize_assessment_embeds_priority():
    assessment = {
        "schema_version": "1.0",
        "assessment": {
            "assessment_id": "assessment-test",
            "timestamp": None,
            "scanner": {
                "name": "Linux Security Checker Pro",
                "version": "1.1.0"
            },
            "score": 50,
            "risk_level": "medium"
        },
        "asset": {
            "asset_id": "host-1",
            "hostname": "host-1",
            "asset_type": "linux_host",
            "operating_system": "Ubuntu",
            "kernel_version": "test",
            "environment": "unknown",
            "internet_exposed": None,
            "business_criticality": "unknown"
        },
        "findings": [
            {
                "finding_id": "LOWER",
                "baseline_severity": "medium"
            },
            {
                "finding_id": "HIGHER",
                "baseline_severity": "high"
            }
        ]
    }

    result = prioritize.prioritize_assessment(assessment)

    assert result["findings"][0]["finding_id"] == "HIGHER"
    assert result["findings"][0]["priority"]["score"] == 4
    assert result["findings"][1]["priority"]["score"] == 3

    # Raw input must remain unchanged.
    assert "priority" not in assessment["findings"][0]
    assert "priority" not in assessment["findings"][1]
