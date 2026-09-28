# Structured findings pipeline

#!/bin/bash

# Legacy findings pipeline
FINDINGS=()

add_finding() {
    FINDINGS+=("$1")
}

show_findings() {
    echo
    echo "[+] Security Findings:"

    if [ ${#FINDINGS[@]} -eq 0 ]; then
        echo " NO findings detected"
        return
    fi

    for finding in "${FINDINGS[@]}"; do
        echo "- $finding"
    done
}
STRUCTURED_FINDINGS_FILE="${STRUCTURED_FINDINGS_FILE:-report/structured-findings.jsonl}"

init_structured_findings() {
    mkdir -p "$(dirname "$STRUCTURED_FINDINGS_FILE")"
    : > "$STRUCTURED_FINDINGS_FILE"
}

add_structured_finding() {
    local finding_id="$1"
    local category="$2"
    local title="$3"
    local severity="$4"
    local source_type="$5"
    local source_module="$6"
    local evidence_type="$7"
    local evidence_source="$8"
    local evidence_key="$9"
    local observed_value="${10}"
    local recommendation="${11}"

    python3 - \
        "$STRUCTURED_FINDINGS_FILE" \
        "$finding_id" \
        "$category" \
        "$title" \
        "$severity" \
        "$source_type" \
        "$source_module" \
        "$evidence_type" \
        "$evidence_source" \
        "$evidence_key" \
        "$observed_value" \
        "$recommendation" <<'PY'
import json
import sys

(
    output_file,
    finding_id,
    category,
    title,
    severity,
    source_type,
    source_module,
    evidence_type,
    evidence_source,
    evidence_key,
    observed_value,
    recommendation,
) = sys.argv[1:]

finding = {
    "finding_id": finding_id,
    "category": category,
    "title": title,
    "baseline_severity": severity.lower(),
    "status": "open",
    "source": {
        "type": source_type,
        "module": source_module
    },
    "evidence": {
        "type": evidence_type,
        "source": evidence_source,
        "key": evidence_key,
        "observed_value": observed_value
    },
    "classification": {
        "cve": None,
        "cwe": None,
        "cvss": None
    },
    "remediation": {
        "recommendation": recommendation,
        "approval_status": "pending",
        "applied": False
    },
    "verification": {
        "security": "not_tested",
        "configuration": "not_tested",
        "functionality": "not_tested"
    }
}

with open(output_file, "a", encoding="utf-8") as f:
    f.write(json.dumps(finding, separators=(",", ":")) + "\n")
PY
}

add_package_inventory_finding() {
    local finding_id="$1"
    local category="$2"
    local title="$3"
    local severity="$4"
    local source_module="$5"
    local package_manager="$6"
    local update_count="$7"
    local security_updates_confirmed="$8"
    local recommendation="$9"

    python3 - \
        "$STRUCTURED_FINDINGS_FILE" \
        "$finding_id" \
        "$category" \
        "$title" \
        "$severity" \
        "$source_module" \
        "$package_manager" \
        "$update_count" \
        "$security_updates_confirmed" \
        "$recommendation" <<'PY'
import json
import sys

(
    output_file,
    finding_id,
    category,
    title,
    severity,
    source_module,
    package_manager,
    update_count,
    security_updates_confirmed,
    recommendation,
) = sys.argv[1:]

finding = {
    "finding_id": finding_id,
    "category": category,
    "title": title,
    "baseline_severity": severity.lower(),
    "status": "open",
    "source": {
        "type": "linux_package_inventory",
        "module": source_module
    },
    "evidence": {
        "type": "package_inventory",
        "source": "apt list --upgradable",
        "package_manager": package_manager,
        "update_count": int(update_count),
        "security_updates_confirmed": security_updates_confirmed.lower() == "true"
    },
    "classification": {
        "cve": None,
        "cwe": None,
        "cvss": None
    },
    "remediation": {
        "recommendation": recommendation,
        "approval_status": "pending",
        "applied": False
    },
    "verification": {
        "security": "not_tested",
        "configuration": "not_tested",
        "functionality": "not_tested"
    }
}

with open(output_file, "a", encoding="utf-8") as f:
    f.write(json.dumps(finding, separators=(",", ":")) + "\n")
PY
}

add_socket_finding() {
    local finding_id="$1"
    local category="$2"
    local title="$3"
    local severity="$4"
    local source_module="$5"
    local protocol="$6"
    local bind_address="$7"
    local port="$8"
    local process="$9"
    local recommendation="${10}"

    python3 - \
        "$STRUCTURED_FINDINGS_FILE" \
        "$finding_id" \
        "$category" \
        "$title" \
        "$severity" \
        "$source_module" \
        "$protocol" \
        "$bind_address" \
        "$port" \
        "$process" \
        "$recommendation" <<'PY'
import json
import sys

(
    output_file,
    finding_id,
    category,
    title,
    severity,
    source_module,
    protocol,
    bind_address,
    port,
    process,
    recommendation,
) = sys.argv[1:]

finding = {
    "finding_id": finding_id,
    "category": category,
    "title": title,
    "baseline_severity": severity.lower(),
    "status": "open",
    "source": {
        "type": "linux_network_socket",
        "module": source_module
    },
    "evidence": {
        "type": "socket",
        "source": "ss -lntupH",
        "protocol": protocol.lower(),
        "bind_address": bind_address,
        "port": int(port),
        "process": process if process else None,
        "internet_exposed": "unknown"
    },
    "classification": {
        "cve": None,
        "cwe": None,
        "cvss": None
    },
    "remediation": {
        "recommendation": recommendation,
        "approval_status": "pending",
        "applied": False
    },
    "verification": {
        "security": "not_tested",
        "configuration": "not_tested",
        "functionality": "not_tested"
    }
}

with open(output_file, "a", encoding="utf-8") as f:
    f.write(json.dumps(finding, separators=(",", ":")) + "\n")
PY
}
