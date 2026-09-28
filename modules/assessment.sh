#!/bin/bash

generate_assessment_json() {
    local output_file="${1:-report/assessment.json}"
    local findings_file="${STRUCTURED_FINDINGS_FILE:-report/structured-findings.jsonl}"

    mkdir -p "$(dirname "$output_file")"

    local scanner_version="unknown"
    if [ -f version.txt ]; then
        scanner_version="$(tr -d '\r\n' < version.txt)"
    fi

    local hostname_value
    hostname_value="$(hostname 2>/dev/null || echo unknown)"

    local os_value
    os_value="$(grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d '"' -f2)"
    [ -n "$os_value" ] || os_value="unknown"

    local kernel_value
    kernel_value="$(uname -r 2>/dev/null || echo unknown)"

    local timestamp_value
    timestamp_value="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    local assessment_id
    assessment_id="assessment-${hostname_value}-$(date -u +"%Y%m%dT%H%M%SZ")"

    local score_value="0"
    if [ -f /tmp/security_score ]; then
        score_value="$(cat /tmp/security_score)"
    fi

    local risk_value="${RISK_LEVEL:-UNKNOWN}"

    python3 - "$findings_file" "$output_file" \
        "$assessment_id" "$timestamp_value" \
        "$scanner_version" "$hostname_value" \
        "$os_value" "$kernel_value" \
        "$score_value" "$risk_value" <<'PY'
import json
import pathlib
import sys

(
    findings_file,
    output_file,
    assessment_id,
    timestamp,
    scanner_version,
    hostname,
    operating_system,
    kernel_version,
    score,
    risk_level,
) = sys.argv[1:]

findings = []

path = pathlib.Path(findings_file)
if path.exists():
    for line_number, line in enumerate(path.read_text().splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SystemExit(
                f"Invalid JSON in {findings_file} at line {line_number}: {exc}"
            )

assessment = {
    "schema_version": "1.0",
    "assessment": {
        "assessment_id": assessment_id,
        "timestamp": timestamp,
        "scanner": {
            "name": "Linux Security Checker Pro",
            "version": scanner_version
        },
        "score": int(score),
        "risk_level": risk_level.lower()
    },
    "asset": {
        "asset_id": hostname,
        "hostname": hostname,
        "asset_type": "linux_host",
        "operating_system": operating_system,
        "kernel_version": kernel_version,
        "environment": "unknown",
        "internet_exposed": None,
        "business_criticality": "unknown"
    },
    "findings": findings
}

pathlib.Path(output_file).write_text(
    json.dumps(assessment, indent=2) + "\n"
)

print(
    f"[+] Structured Assessment Created: "
    f"{output_file} ({len(findings)} findings)"
)
PY
}
