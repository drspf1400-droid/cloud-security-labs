#!/usr/bin/env python3

import hashlib
import json
from copy import deepcopy
from pathlib import Path

from jsonschema import ValidationError, validate


ROOT = Path(__file__).resolve().parents[1]

MODEL_OUTPUT_FIELDS = {
    "risk_summary",
    "evidence_interpretation",
    "recommended_action",
    "confidence",
    "confidence_basis",
    "priority_recommendation",
    "evidence_refs",
    "limitations",
}


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_value(value):
    return hashlib.sha256(
        canonical_json(value)
    ).hexdigest()


def build_analysis_request(finding, asset):
    allowed_evidence_refs = [
        "finding.evidence",
        "finding.baseline_severity",
        "asset.environment",
        "asset.internet_exposed",
        "asset.business_criticality",
    ]

    if finding.get("priority") is not None:
        allowed_evidence_refs.append(
            "finding.priority"
        )

    return {
        "finding": {
            "finding_id": finding["finding_id"],
            "category": finding["category"],
            "title": finding["title"],
            "baseline_severity": (
                finding["baseline_severity"]
            ),
            "priority": deepcopy(
                finding.get("priority")
            ),
            "evidence": deepcopy(
                finding["evidence"]
            ),
        },
        "asset": {
            "environment": asset.get(
                "environment"
            ),
            "internet_exposed": asset.get(
                "internet_exposed"
            ),
            "business_criticality": asset.get(
                "business_criticality"
            ),
        },
        "guardrails": {
            "advisory_only": True,
            "human_review_required": True,
            "execution_authorized": False,
            "allowed_evidence_refs":
                allowed_evidence_refs,
        },
    }


def normalize_model_output(
    *,
    finding,
    request,
    model_output,
    provider_name,
    model_name,
):
    if not isinstance(model_output, dict):
        raise ValueError(
            "AI analyzer output must be a JSON object"
        )

    unexpected = (
        set(model_output)
        - MODEL_OUTPUT_FIELDS
    )

    if unexpected:
        raise ValueError(
            "AI analyzer attempted unsupported "
            "fields: "
            + ", ".join(sorted(unexpected))
        )

    allowed_refs = set(
        request["guardrails"][
            "allowed_evidence_refs"
        ]
    )

    evidence_refs = model_output.get(
        "evidence_refs",
        [],
    )

    unknown_refs = (
        set(evidence_refs) - allowed_refs
    )

    if unknown_refs:
        raise ValueError(
            "AI analysis referenced unavailable "
            "evidence: "
            + ", ".join(sorted(unknown_refs))
        )

    return {
        "finding_id": finding["finding_id"],
        "provider": {
            "name": provider_name,
            "model": model_name,
        },
        "risk_summary":
            model_output.get("risk_summary"),
        "evidence_interpretation":
            model_output.get(
                "evidence_interpretation",
                [],
            ),
        "recommended_action":
            model_output.get(
                "recommended_action"
            ),
        "confidence":
            model_output.get("confidence"),
        "confidence_basis":
            model_output.get(
                "confidence_basis",
                [],
            ),
        "priority_recommendation":
            model_output.get(
                "priority_recommendation"
            ),
        "evidence_refs": evidence_refs,
        "limitations":
            model_output.get(
                "limitations",
                [],
            ),
        "requires_human_review": True,
        "execution_authorized": False,
        "input_sha256": sha256_value(
            request
        ),
    }


def validate_ai_analysis_report(report):
    schema_path = (
        ROOT
        / "schemas"
        / "ai-analysis-report-schema.json"
    )

    schema = json.loads(
        schema_path.read_text(
            encoding="utf-8"
        )
    )

    try:
        validate(
            instance=report,
            schema=schema,
        )
    except ValidationError as exc:
        raise ValueError(
            "AI analysis report failed schema "
            f"validation: {exc.message}"
        ) from exc


def analyze_assessment(
    assessment,
    analyzer,
    *,
    provider_name,
    model_name,
):
    if not callable(analyzer):
        raise ValueError(
            "AI analyzer must be callable"
        )

    analyses = []

    for finding in assessment["findings"]:
        request = build_analysis_request(
            finding,
            assessment["asset"],
        )

        raw_output = analyzer(
            deepcopy(request)
        )

        analyses.append(
            normalize_model_output(
                finding=finding,
                request=request,
                model_output=raw_output,
                provider_name=provider_name,
                model_name=model_name,
            )
        )

    report = {
        "schema_version": "1.0",
        "assessment_id": (
            assessment["assessment"][
                "assessment_id"
            ]
        ),
        "source_assessment_sha256":
            sha256_value(assessment),
        "advisory_only": True,
        "analyses": analyses,
    }

    validate_ai_analysis_report(report)

    return report
