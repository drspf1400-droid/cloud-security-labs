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

    assert result["priority_score"] == 4
    assert result["priority_reasons"] == [
        "baseline_severity=high"
    ]


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

    assert result["priority_score"] == 6
    assert "internet_exposed=true" in result["priority_reasons"]
    assert "business_criticality=critical" in result["priority_reasons"]
    assert "environment=production" in result["priority_reasons"]


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

    assert result["priority_score"] == 3
