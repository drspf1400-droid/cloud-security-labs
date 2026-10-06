#!/usr/bin/env python3


def deterministic_mock_analyzer(request):
    finding = request["finding"]
    evidence = finding["evidence"]

    evidence_refs = [
        "finding.evidence",
        "finding.baseline_severity",
    ]

    if finding.get("priority") is not None:
        evidence_refs.append(
            "finding.priority"
        )

    finding_id = finding["finding_id"]

    if (
        finding_id == "SSH-002"
        and evidence.get("type")
        == "configuration"
        and evidence.get("key")
        == "PermitRootLogin"
    ):
        observed = str(
            evidence.get(
                "observed_value",
                "",
            )
        ).lower()

        permitted = observed in {
            "yes",
            "without-password",
            "prohibit-password",
        }

        if permitted:
            return {
                "risk_summary": (
                    "Direct SSH root login is permitted "
                    "and increases administrative risk."
                ),
                "evidence_interpretation": [
                    (
                        "PermitRootLogin is configured "
                        f"as {observed}."
                    ),
                    (
                        "The supplied configuration "
                        "evidence directly supports "
                        "the finding."
                    ),
                ],
                "recommended_action": (
                    "Disable direct SSH root login "
                    "after human review and verify "
                    "the effective SSH configuration."
                ),
                "confidence": 0.95,
                "confidence_basis": [
                    (
                        "The finding is supported by "
                        "explicit configuration evidence."
                    )
                ],
                "priority_recommendation": "keep",
                "evidence_refs": evidence_refs,
                "limitations": [
                    (
                        "External reachability was not "
                        "independently verified."
                    )
                ],
            }

    return {
        "risk_summary": (
            "The finding requires human review "
            "using the supplied evidence."
        ),
        "evidence_interpretation": [
            (
                "Analysis is limited to the evidence "
                "included in the assessment."
            )
        ],
        "recommended_action": (
            "Review the finding and supporting evidence "
            "before approving any remediation."
        ),
        "confidence": 0.60,
        "confidence_basis": [
            (
                "A deterministic fallback analysis "
                "was used."
            )
        ],
        "priority_recommendation": "keep",
        "evidence_refs": evidence_refs,
        "limitations": [
            (
                "No external intelligence or live "
                "system context was used."
            )
        ],
    }

import json
import urllib.error
import urllib.request
from urllib.parse import urlparse


class LocalLLMProviderError(RuntimeError):
    pass


MAX_OLLAMA_RESPONSE_BYTES = 262144


def validate_local_ollama_endpoint(endpoint):
    parsed = urlparse(endpoint)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            "Ollama endpoint must use http or https"
        )

    if parsed.hostname not in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        raise ValueError(
            "Ollama endpoint must be local"
        )


def ollama_json_analyzer(
    request,
    *,
    endpoint="http://127.0.0.1:11434/api/chat",
    model="qwen2.5:3b",
    timeout=60,
):
    validate_local_ollama_endpoint(endpoint)

    system_prompt = """
You are a security analysis assistant.

You MUST:
- analyze only the supplied evidence
- never authorize execution
- never change finding status
- never approve remediation
- never invent unavailable evidence
- return JSON only

Return exactly these fields:
risk_summary
evidence_interpretation
recommended_action
confidence
confidence_basis
priority_recommendation
evidence_refs
limitations

priority_recommendation must be one of:
increase, keep, decrease

confidence must be between 0 and 1.
"""

    user_prompt = json.dumps(
        request,
        ensure_ascii=False,
        sort_keys=True,
    )

    payload = {
        "model": model,
        "stream": False,
        "format": "json",
        "messages": [
            {
                "role": "system",
                "content": system_prompt.strip(),
            },
            {
                "role": "user",
                "content": user_prompt,
            },
        ],
    }

    encoded = json.dumps(
        payload
    ).encode("utf-8")

    http_request = urllib.request.Request(
        endpoint,
        data=encoded,
        headers={
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            http_request,
            timeout=timeout,
        ) as response:
            body = response.read(
                MAX_OLLAMA_RESPONSE_BYTES + 1
            )

            if (
                len(body)
                > MAX_OLLAMA_RESPONSE_BYTES
            ):
                raise LocalLLMProviderError(
                    "Local LLM response exceeded "
                    "the size limit"
                )

    except (
        urllib.error.URLError,
        TimeoutError,
    ) as exc:
        raise LocalLLMProviderError(
            f"Local LLM request failed: {exc}"
        ) from exc

    try:
        outer = json.loads(
            body.decode("utf-8")
        )

        content = outer["message"]["content"]

        result = json.loads(content)

    except (
        KeyError,
        TypeError,
        ValueError,
        UnicodeDecodeError,
    ) as exc:
        raise LocalLLMProviderError(
            "Local LLM returned invalid JSON output"
        ) from exc

    if not isinstance(result, dict):
        raise LocalLLMProviderError(
            "Local LLM output must be a JSON object"
        )

    return result
