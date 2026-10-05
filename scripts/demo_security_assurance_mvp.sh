#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${1:-/tmp/cloud-security-labs-mvp-demo}"

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

ASSESSMENT="$WORKDIR/assessment.json"
CONTEXT="$WORKDIR/execution-context.json"
TARGET="$WORKDIR/sshd_config"
OUTPUT="$WORKDIR/output"

cp \
  "$ROOT/tests/fixtures/sshd_config.insecure" \
  "$TARGET"

python3 - "$ASSESSMENT" "$CONTEXT" "$TARGET" <<'PY'
import json
import sys
from pathlib import Path

assessment_path = Path(sys.argv[1])
context_path = Path(sys.argv[2])
target_path = Path(sys.argv[3])

assessment = {
    "schema_version": "1.0",
    "assessment": {
        "assessment_id": "MVP-DEMO-001",
        "scanner": {
            "name": "linux-security-checker",
            "version": "15"
        },
        "score": 60,
        "risk_level": "high"
    },
    "asset": {
        "asset_id": "DEMO-LINUX-001",
        "hostname": "demo-linux-host",
        "asset_type": "linux_server",
        "environment": "lab",
        "internet_exposed": False,
        "business_criticality": "medium"
    },
    "findings": [
        {
            "finding_id": "SSH-002",
            "category": "ssh",
            "title": "SSH root login permitted",
            "baseline_severity": "high",
            "status": "approved",
            "source": {
                "type": "linux_configuration",
                "module": "ssh_check"
            },
            "evidence": {
                "type": "configuration",
                "source": "/etc/ssh/sshd_config",
                "key": "PermitRootLogin",
                "observed_value": "yes"
            },
            "classification": {
                "cve": None,
                "cwe": None,
                "cvss": None
            },
            "remediation": {
                "recommendation": (
                    "Disable direct SSH root login."
                ),
                "approval_status": "approved",
                "applied": False
            },
            "verification": {
                "security": "not_tested",
                "configuration": "not_tested",
                "functionality": "not_tested"
            }
        }
    ]
}

context = {
    "SSH-002": {
        "config_path": str(target_path)
    }
}

assessment_path.write_text(
    json.dumps(assessment, indent=2) + "\n",
    encoding="utf-8",
)

context_path.write_text(
    json.dumps(context, indent=2) + "\n",
    encoding="utf-8",
)
PY

echo
echo "=== Before remediation ==="
grep -n "PermitRootLogin" "$TARGET"

python3 "$ROOT/scripts/run_security_assurance_mvp.py" \
  --assessment "$ASSESSMENT" \
  --trust-report "$ROOT/report/trust_decision_report.json" \
  --environment lab \
  --execute-remediation \
  --actor demo-security-reviewer \
  --execution-context "$CONTEXT" \
  --output-dir "$OUTPUT" \
  --enforce-gate

echo
echo "=== After remediation ==="
grep -n "PermitRootLogin" "$TARGET"

python3 - "$OUTPUT" <<'PY'
import json
import sys
from pathlib import Path

base = Path(sys.argv[1])

assessment = json.loads(
    (base / "04_execution_assessment.json").read_text()
)

report = json.loads(
    (base / "security_assurance_report.json").read_text()
)

gate = json.loads(
    (base / "security_gate_result.json").read_text()
)

evidence = json.loads(
    (base / "execution_evidence.json").read_text()
)

finding = assessment["findings"][0]
execution = assessment["assessment"]["execution"]["summary"]

print()
print("=== MVP Demo Result ===")
print("Finding status:", finding["status"])
print("Remediation applied:", finding["remediation"]["applied"])
print("Verification passed:", finding["remediation"]["verified"])
print("Execution summary:", execution)
print(
    "Assurance state:",
    report["executive_summary"]["assurance_state"],
)
print("Security gate:", gate["decision"])
print(
    "Evidence SHA-256:",
    evidence["integrity"]["sha256"],
)
print(
    "HTML report:",
    base / "security_assurance_report.html",
)
PY

echo
echo "Demo completed successfully."
echo "Artifacts: $OUTPUT"
