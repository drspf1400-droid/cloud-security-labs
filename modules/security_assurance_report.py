#!/usr/bin/env python3

from copy import deepcopy
from datetime import datetime, timezone
from html import escape
import json
from uuid import uuid4


REPORT_VERSION = "1.0"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def count_findings(findings, severity):
    return sum(
        1
        for finding in findings
        if finding.get("baseline_severity") == severity
    )


def summarize_finding(finding):
    remediation = finding.get(
        "remediation",
        {},
    )

    return {
        "finding_id": finding.get("finding_id"),
        "title": finding.get("title"),
        "category": finding.get("category"),
        "severity": finding.get(
            "baseline_severity"
        ),
        "status": finding.get("status"),
        "recommendation": remediation.get(
            "recommendation"
        ),
        "approval_status": remediation.get(
            "approval_status"
        ),
        "remediation_applied": remediation.get(
            "applied",
            False,
        ),
    }


def build_security_assurance_report(
    assessment,
    trust_report=None,
    *,
    report_id=None,
    generated_at=None,
):
    """
    Build a machine-readable Security Assurance Report
    without mutating the source assessment.
    """

    source = deepcopy(assessment)
    trust_source = deepcopy(
        trust_report or {}
    )

    if report_id is None:
        report_id = str(uuid4())

    if generated_at is None:
        generated_at = utc_now()

    assessment_meta = source.get(
        "assessment",
        {},
    )

    asset = source.get(
        "asset",
        {},
    )

    findings = source.get(
        "findings",
        [],
    )

    policy = assessment_meta.get(
        "remediation_policy",
        {},
    )

    execution_plan = assessment_meta.get(
        "execution_plan",
        {},
    )

    execution = assessment_meta.get(
        "execution",
        {},
    )

    evidence = assessment_meta.get(
        "execution_evidence",
        {},
    )

    verification = trust_source.get(
        "verification",
        {},
    )

    trust_decision = verification.get(
        "effective_decision",
        "unknown",
    )

    policy_summary = deepcopy(
        policy.get(
            "summary",
            {
                "apply": 0,
                "dry_run": 0,
                "blocked": 0,
            },
        )
    )

    execution_summary = deepcopy(
        execution.get(
            "summary",
            {
                "executed": 0,
                "dry_run": 0,
                "blocked": 0,
                "failed": 0,
            },
        )
    )

    failed = execution_summary.get(
        "failed",
        0,
    )

    blocked = execution_summary.get(
        "blocked",
        0,
    )

    resolved_statuses = {
        "remediated",
        "accepted",
        "false_positive",
    }

    unresolved_severe = sum(
        1
        for finding in findings
        if (
            finding.get("baseline_severity")
            in {"high", "critical"}
            and finding.get("status")
            not in resolved_statuses
        )
    )

    if (
        trust_decision == "reject"
        or failed > 0
        or unresolved_severe > 0
    ):
        assurance_state = "attention_required"

    elif (
        trust_decision == "accept"
        and blocked == 0
    ):
        assurance_state = "verified"

    else:
        assurance_state = "partial"

    integrity = evidence.get(
        "integrity",
        {},
    )

    provenance = evidence.get(
        "provenance",
        {},
    )

    controls = {
        "human_review_present": any(
            finding.get("status")
            in {
                "approved",
                "accepted",
                "false_positive",
                "remediated",
            }
            for finding in findings
        ),
        "policy_guardrails_present": bool(
            policy
        ),
        "execution_plan_present": bool(
            execution_plan
        ),
        "execution_evidence_present": bool(
            evidence
        ),
        "integrity_hash_present": bool(
            integrity.get("sha256")
        ),
        "cryptographic_provenance_present": bool(
            provenance.get("signature")
        ),
        "trust_decision_present": (
            trust_decision
            in {"accept", "reject"}
        ),
    }

    return {
        "report_version": REPORT_VERSION,
        "report_type": "security_assurance",
        "report_id": report_id,
        "generated_at": generated_at,

        "executive_summary": {
            "assessment_id": assessment_meta.get(
                "assessment_id"
            ),
            "security_score": assessment_meta.get(
                "score"
            ),
            "risk_level": assessment_meta.get(
                "risk_level"
            ),
            "assurance_state": assurance_state,
            "total_findings": len(findings),
            "critical_findings": count_findings(
                findings,
                "critical",
            ),
            "high_findings": count_findings(
                findings,
                "high",
            ),
            "policy_decisions": policy_summary,
            "execution_outcomes": execution_summary,
            "trust_decision": trust_decision,
        },

        "asset": {
            "asset_id": asset.get("asset_id"),
            "hostname": asset.get("hostname"),
            "asset_type": asset.get(
                "asset_type"
            ),
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

        "assurance_controls": controls,

        "trust_assurance": {
            "effective_decision": trust_decision,
            "decision_basis": verification.get(
                "decision_basis"
            ),
            "signature_valid": verification.get(
                "signature_valid"
            ),
            "signer_id": (
                trust_source
                .get("signer", {})
                .get("signer_id")
            ),
            "key_id": (
                trust_source
                .get("signer", {})
                .get("key_id")
            ),
            "key_status": (
                trust_source
                .get("signer", {})
                .get("key_status")
            ),
        },

        "findings": [
            summarize_finding(finding)
            for finding in findings
        ],
    }


def render_security_assurance_html(report):
    summary = report["executive_summary"]
    asset = report["asset"]
    controls = report["assurance_controls"]
    trust = report["trust_assurance"]

    finding_rows = []

    for finding in report.get("findings", []):
        finding_rows.append(
            "<tr>"
            f"<td>{escape(str(finding.get('finding_id') or ''))}</td>"
            f"<td>{escape(str(finding.get('title') or ''))}</td>"
            f"<td>{escape(str(finding.get('severity') or ''))}</td>"
            f"<td>{escape(str(finding.get('status') or ''))}</td>"
            f"<td>{escape(str(finding.get('recommendation') or ''))}</td>"
            "</tr>"
        )

    control_rows = []

    for name, enabled in controls.items():
        control_rows.append(
            "<tr>"
            f"<td>{escape(name.replace('_', ' ').title())}</td>"
            f"<td>{'YES' if enabled else 'NO'}</td>"
            "</tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Assurance Report</title>

<style>
body {{
    font-family: Arial, sans-serif;
    background: #f5f7fa;
    color: #1f2937;
    margin: 40px;
}}

.container {{
    max-width: 1100px;
    margin: auto;
    background: white;
    padding: 32px;
    border-radius: 10px;
}}

.grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
}}

.card {{
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 16px;
}}

.label {{
    color: #6b7280;
    font-size: 12px;
    text-transform: uppercase;
}}

.value {{
    font-size: 22px;
    font-weight: bold;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 30px;
}}

th, td {{
    border-bottom: 1px solid #e5e7eb;
    padding: 10px;
    text-align: left;
}}

th {{
    background: #f9fafb;
}}

.meta {{
    color: #6b7280;
    font-size: 13px;
}}
</style>
</head>

<body>

<div class="container">

<h1>Security Assurance Report</h1>

<p class="meta">
Report ID: {escape(str(report["report_id"]))}<br>
Generated: {escape(str(report["generated_at"]))}
</p>

<h2>Executive Summary</h2>

<div class="grid">

<div class="card">
<div class="label">Security Score</div>
<div class="value">{escape(str(summary.get("security_score")))}</div>
</div>

<div class="card">
<div class="label">Risk Level</div>
<div class="value">{escape(str(summary.get("risk_level")))}</div>
</div>

<div class="card">
<div class="label">Assurance State</div>
<div class="value">{escape(str(summary.get("assurance_state")))}</div>
</div>

<div class="card">
<div class="label">Trust Decision</div>
<div class="value">{escape(str(summary.get("trust_decision")))}</div>
</div>

</div>

<h2>Asset Context</h2>

<table>
<tr><th>Asset ID</th><td>{escape(str(asset.get("asset_id")))}</td></tr>
<tr><th>Hostname</th><td>{escape(str(asset.get("hostname")))}</td></tr>
<tr><th>Asset Type</th><td>{escape(str(asset.get("asset_type")))}</td></tr>
<tr><th>Environment</th><td>{escape(str(asset.get("environment")))}</td></tr>
</table>

<h2>Assurance Controls</h2>

<table>
<tr>
<th>Control</th>
<th>Present</th>
</tr>

{''.join(control_rows)}

</table>

<h2>Trust Assurance</h2>

<table>
<tr><th>Effective Decision</th><td>{escape(str(trust.get("effective_decision")))}</td></tr>
<tr><th>Decision Basis</th><td>{escape(str(trust.get("decision_basis")))}</td></tr>
<tr><th>Signature Valid</th><td>{escape(str(trust.get("signature_valid")))}</td></tr>
<tr><th>Signer</th><td>{escape(str(trust.get("signer_id")))}</td></tr>
<tr><th>Key ID</th><td>{escape(str(trust.get("key_id")))}</td></tr>
<tr><th>Key Status</th><td>{escape(str(trust.get("key_status")))}</td></tr>
</table>

<h2>Security Findings</h2>

<table>

<tr>
<th>ID</th>
<th>Title</th>
<th>Severity</th>
<th>Status</th>
<th>Recommendation</th>
</tr>

{''.join(finding_rows)}

</table>

</div>

</body>
</html>
"""


def write_security_assurance_report(
    report,
    *,
    json_path,
    html_path,
):
    with open(
        json_path,
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            report,
            handle,
            indent=2,
            ensure_ascii=False,
        )
        handle.write("\n")

    with open(
        html_path,
        "w",
        encoding="utf-8",
    ) as handle:
        handle.write(
            render_security_assurance_html(
                report
            )
        )
