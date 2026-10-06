import json
import urllib.error

import pytest

from modules.ai_analysis import (
    analyze_assessment,
)

from modules.ai_providers import (
    LocalLLMProviderError,
    ollama_json_analyzer,
)


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ):
        return False

    def read(self, size=-1):
        data = json.dumps(
            self.payload
        ).encode("utf-8")

        if size is None or size < 0:
            return data

        return data[:size]


def valid_model_output():
    return {
        "risk_summary":
            "SSH root login increases risk.",
        "evidence_interpretation": [
            (
                "PermitRootLogin is explicitly "
                "enabled."
            )
        ],
        "recommended_action":
            (
                "Disable direct root login "
                "after human review."
            ),
        "confidence": 0.91,
        "confidence_basis": [
            (
                "Explicit configuration "
                "evidence was supplied."
            )
        ],
        "priority_recommendation": "keep",
        "evidence_refs": [
            "finding.evidence",
            "finding.baseline_severity",
        ],
        "limitations": [
            (
                "External reachability was "
                "not verified."
            )
        ],
    }


def sample_request():
    return {
        "finding": {
            "finding_id": "SSH-002",
            "category": "ssh",
            "title": "SSH root login permitted",
            "baseline_severity": "high",
            "priority": None,
            "evidence": {
                "type": "configuration",
                "source":
                    "/etc/ssh/sshd_config",
                "key": "PermitRootLogin",
                "observed_value": "yes",
            },
        },
        "asset": {
            "environment": "lab",
            "internet_exposed": False,
            "business_criticality": "medium",
        },
        "guardrails": {
            "advisory_only": True,
            "human_review_required": True,
            "execution_authorized": False,
            "allowed_evidence_refs": [
                "finding.evidence",
                "finding.baseline_severity",
                "asset.environment",
                "asset.internet_exposed",
                "asset.business_criticality",
            ],
        },
    }


def sample_assessment():
    return {
        "schema_version": "1.0",
        "assessment": {
            "assessment_id": "OLLAMA-TEST-001",
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
                "title":
                    "SSH root login permitted",
                "baseline_severity": "high",
                "status": "open",
                "source": {
                    "type":
                        "linux_configuration",
                    "module": "ssh_check",
                },
                "evidence": {
                    "type": "configuration",
                    "source":
                        "/etc/ssh/sshd_config",
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
                        (
                            "Disable direct "
                            "SSH root login."
                        ),
                    "approval_status": "pending",
                    "applied": False,
                },
                "verification": {
                    "security": "not_tested",
                    "configuration":
                        "not_tested",
                    "functionality":
                        "not_tested",
                },
            }
        ],
    }


def test_ollama_provider_returns_json(
    monkeypatch,
):
    model_output = valid_model_output()

    payload = {
        "message": {
            "content": json.dumps(
                model_output
            )
        }
    }

    def fake_urlopen(
        request,
        timeout,
    ):
        assert timeout == 15

        sent = json.loads(
            request.data.decode("utf-8")
        )

        assert sent["model"] == \
            "security-model"

        assert sent["stream"] is False
        assert sent["format"] == "json"

        return FakeResponse(payload)

    monkeypatch.setattr(
        "modules.ai_providers."
        "urllib.request.urlopen",
        fake_urlopen,
    )

    result = ollama_json_analyzer(
        sample_request(),
        model="security-model",
        timeout=15,
    )

    assert result == model_output


def test_ollama_invalid_json_fails_closed(
    monkeypatch,
):
    payload = {
        "message": {
            "content": "not-json"
        }
    }

    monkeypatch.setattr(
        "modules.ai_providers."
        "urllib.request.urlopen",
        lambda request, timeout:
            FakeResponse(payload),
    )

    with pytest.raises(
        LocalLLMProviderError,
        match="invalid JSON",
    ):
        ollama_json_analyzer(
            sample_request()
        )


def test_ollama_connection_failure_fails_closed(
    monkeypatch,
):
    def fail_request(
        request,
        timeout,
    ):
        raise urllib.error.URLError(
            "connection refused"
        )

    monkeypatch.setattr(
        "modules.ai_providers."
        "urllib.request.urlopen",
        fail_request,
    )

    with pytest.raises(
        LocalLLMProviderError,
        match="request failed",
    ):
        ollama_json_analyzer(
            sample_request()
        )


def test_ollama_cannot_authorize_execution(
    monkeypatch,
):
    unsafe = valid_model_output()

    unsafe[
        "execution_authorized"
    ] = True

    payload = {
        "message": {
            "content": json.dumps(
                unsafe
            )
        }
    }

    monkeypatch.setattr(
        "modules.ai_providers."
        "urllib.request.urlopen",
        lambda request, timeout:
            FakeResponse(payload),
    )

    def analyzer(request):
        return ollama_json_analyzer(
            request
        )

    with pytest.raises(
        ValueError,
        match="unsupported fields",
    ):
        analyze_assessment(
            sample_assessment(),
            analyzer,
            provider_name="ollama",
            model_name="security-model",
        )


def test_ollama_rejects_nonlocal_endpoint():
    with pytest.raises(
        ValueError,
        match="must be local",
    ):
        ollama_json_analyzer(
            sample_request(),
            endpoint=(
                "http://example.com:11434/api/chat"
            ),
        )


def test_ollama_rejects_unsupported_scheme():
    with pytest.raises(
        ValueError,
        match="http or https",
    ):
        ollama_json_analyzer(
            sample_request(),
            endpoint=(
                "file:///tmp/ollama"
            ),
        )
