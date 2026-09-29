#!/usr/bin/env python3

import argparse
import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from modules.remediation_policy import evaluate_remediation_policy


REMEDIATION_CATALOG = {
    "SSH-002": {
        "action": "disable_ssh_root_login",
        "description": "Disable direct SSH root login.",
        "verification": "Verify that PermitRootLogin is disabled.",
    },
}


def utc_now():
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def find_finding(assessment, finding_id):
    for finding in assessment["findings"]:
        if finding["finding_id"] == finding_id:
            return finding

    raise ValueError(f"Finding not found: {finding_id}")


def ensure_remediation_approved(finding):
    if finding.get("status") != "approved":
        raise ValueError(
            "Remediation blocked: finding status must be approved"
        )

    remediation = finding.get("remediation", {})

    if remediation.get("approval_status") != "approved":
        raise ValueError(
            "Remediation blocked: human approval is required"
        )



def ensure_policy_allows_apply(
    finding,
    environment="lab",
):
    result = evaluate_remediation_policy(
        finding,
        environment=environment,
    )

    if result["decision"] != "apply":
        raise ValueError(
            "Remediation blocked by policy: "
            + result["reason"]
        )

    return result

def build_remediation_plan(finding):
    finding_id = finding["finding_id"]

    if finding_id not in REMEDIATION_CATALOG:
        raise ValueError(
            f"No remediation implementation for finding: {finding_id}"
        )

    catalog_entry = REMEDIATION_CATALOG[finding_id]

    return {
        "finding_id": finding_id,
        "action": catalog_entry["action"],
        "recommendation": finding["remediation"]["recommendation"],
        "description": catalog_entry["description"],
        "verification": catalog_entry["verification"],
        "mode": "dry-run",
    }


def dry_run_finding(
    finding,
    actor,
    note=None,
    timestamp=None,
):
    ensure_remediation_approved(finding)

    plan = build_remediation_plan(finding)
    ts = timestamp or utc_now()

    remediation = finding.setdefault("remediation", {})
    remediation.setdefault("applied", False)

    remediation["plan"] = plan
    remediation["last_mode"] = "dry-run"
    remediation["last_attempt_at"] = ts

    finding.setdefault("audit_trail", [])

    finding["audit_trail"].append({
        "timestamp": ts,
        "actor": actor,
        "action": "remediation_dry_run",
        "from_status": finding["status"],
        "to_status": finding["status"],
        "mode": "dry-run",
        "remediation_action": plan["action"],
        "applied": False,
        "note": note,
    })

    return finding


def dry_run_assessment(
    assessment,
    finding_id,
    actor,
    note=None,
):
    result = deepcopy(assessment)

    finding = find_finding(result, finding_id)

    dry_run_finding(
        finding=finding,
        actor=actor,
        note=note,
    )

    return result


def set_sshd_directive(config_path, directive, value):
    path = Path(config_path)

    if not path.exists():
        raise ValueError(f"SSH config not found: {path}")

    lines = path.read_text().splitlines(keepends=True)

    pattern = re.compile(
        rf"^(\s*){re.escape(directive)}\s+.*$",
        re.IGNORECASE,
    )

    output = []
    replaced = False

    for line in lines:
        raw = line.rstrip("\n")

        if not raw.lstrip().startswith("#"):
            match = pattern.match(raw)

            if match:
                newline = "\n" if line.endswith("\n") else ""
                output.append(
                    f"{match.group(1)}{directive} {value}{newline}"
                )
                replaced = True
                continue

        output.append(line)

    if not replaced:
        if output and not output[-1].endswith("\n"):
            output[-1] += "\n"

        output.append(f"{directive} {value}\n")

    path.write_text("".join(output))


def verify_sshd_directive(
    config_path,
    directive,
    expected_value,
):
    path = Path(config_path)

    if not path.exists():
        return False

    expected = expected_value.lower()

    for line in path.read_text().splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        parts = stripped.split(None, 1)

        if len(parts) != 2:
            continue

        if parts[0].lower() == directive.lower():
            return parts[1].strip().lower() == expected

    return False


def verify_ssh_root_login_disabled(config_path):
    return verify_sshd_directive(
        config_path,
        "PermitRootLogin",
        "no",
    )


def apply_ssh_root_login_remediation(
    finding,
    config_path,
    actor,
    note=None,
    timestamp=None,
    environment="lab",
):
    ensure_remediation_approved(finding)
    ensure_policy_allows_apply(
        finding,
        environment=environment,
    )

    if finding["finding_id"] != "SSH-002":
        raise ValueError(
            "This remediation implementation only supports SSH-002"
        )

    plan = build_remediation_plan(finding)
    plan["mode"] = "apply"

    ts = timestamp or utc_now()
    previous_status = finding["status"]

    set_sshd_directive(
        config_path,
        "PermitRootLogin",
        "no",
    )

    remediation = finding.setdefault("remediation", {})
    remediation["plan"] = plan
    remediation["last_mode"] = "apply"
    remediation["last_attempt_at"] = ts
    remediation["applied"] = True
    remediation["applied_at"] = ts

    finding.setdefault("audit_trail", [])

    finding["audit_trail"].append({
        "timestamp": ts,
        "actor": actor,
        "action": "remediation_applied",
        "from_status": previous_status,
        "to_status": previous_status,
        "mode": "apply",
        "remediation_action": plan["action"],
        "applied": True,
        "note": note,
    })

    verified = verify_ssh_root_login_disabled(config_path)

    remediation["verified"] = verified
    remediation["verified_at"] = ts

    if not verified:
        finding["audit_trail"].append({
            "timestamp": ts,
            "actor": actor,
            "action": "verification_failed",
            "from_status": previous_status,
            "to_status": previous_status,
            "mode": "verification",
            "remediation_action": plan["action"],
            "applied": True,
            "note": "PermitRootLogin was not verified as disabled.",
        })

        raise RuntimeError(
            "Remediation verification failed"
        )

    finding["status"] = "remediated"

    finding["audit_trail"].append({
        "timestamp": ts,
        "actor": actor,
        "action": "verification_passed",
        "from_status": previous_status,
        "to_status": "remediated",
        "mode": "verification",
        "remediation_action": plan["action"],
        "applied": True,
        "note": "PermitRootLogin verified as disabled.",
    })

    return finding



def safe_apply_ssh_root_login_remediation(
    finding,
    config_path,
    actor,
    note=None,
    timestamp=None,
    environment="lab",
):
    """
    Apply SSH remediation with automatic rollback if
    post-remediation verification fails.
    """
    ensure_remediation_approved(finding)
    ensure_policy_allows_apply(
        finding,
        environment=environment,
    )

    if finding["finding_id"] != "SSH-002":
        raise ValueError(
            "This remediation implementation only supports SSH-002"
        )

    path = Path(config_path)

    if not path.exists():
        raise ValueError(f"SSH config not found: {path}")

    original_content = path.read_text()
    previous_status = finding["status"]
    ts = timestamp or utc_now()

    plan = build_remediation_plan(finding)
    plan["mode"] = "apply"

    remediation = finding.setdefault("remediation", {})
    finding.setdefault("audit_trail", [])

    # Apply controlled remediation.
    set_sshd_directive(
        path,
        "PermitRootLogin",
        "no",
    )

    remediation["plan"] = plan
    remediation["last_mode"] = "apply"
    remediation["last_attempt_at"] = ts
    remediation["applied"] = True
    remediation["applied_at"] = ts
    remediation["rollback_performed"] = False
    remediation["rollback_verified"] = False

    finding["audit_trail"].append({
        "timestamp": ts,
        "actor": actor,
        "action": "remediation_applied",
        "from_status": previous_status,
        "to_status": previous_status,
        "mode": "apply",
        "remediation_action": plan["action"],
        "applied": True,
        "note": note,
    })

    verified = verify_ssh_root_login_disabled(path)

    remediation["verified"] = verified
    remediation["verified_at"] = ts

    if verified:
        finding["status"] = "remediated"

        finding["audit_trail"].append({
            "timestamp": ts,
            "actor": actor,
            "action": "verification_passed",
            "from_status": previous_status,
            "to_status": "remediated",
            "mode": "verification",
            "remediation_action": plan["action"],
            "applied": True,
            "note": "PermitRootLogin verified as disabled.",
        })

        return finding

    # Verification failed: start rollback.
    finding["audit_trail"].append({
        "timestamp": ts,
        "actor": actor,
        "action": "verification_failed",
        "from_status": previous_status,
        "to_status": previous_status,
        "mode": "verification",
        "remediation_action": plan["action"],
        "applied": True,
        "note": "Post-remediation verification failed.",
    })

    finding["audit_trail"].append({
        "timestamp": ts,
        "actor": actor,
        "action": "rollback_started",
        "from_status": previous_status,
        "to_status": previous_status,
        "mode": "rollback",
        "remediation_action": plan["action"],
        "applied": True,
        "note": "Restoring pre-remediation configuration.",
    })

    # Restore exact pre-remediation content.
    path.write_text(original_content)

    rollback_verified = (
        path.read_text() == original_content
    )

    remediation["rollback_performed"] = True
    remediation["rollback_verified"] = rollback_verified
    remediation["rollback_at"] = ts
    remediation["applied"] = False

    # Finding remains approved because the security issue
    # is unresolved after rollback.
    finding["status"] = previous_status

    if rollback_verified:
        finding["audit_trail"].append({
            "timestamp": ts,
            "actor": actor,
            "action": "rollback_completed",
            "from_status": previous_status,
            "to_status": previous_status,
            "mode": "rollback",
            "remediation_action": plan["action"],
            "applied": False,
            "note": "Original configuration restored and verified.",
        })

        raise RuntimeError(
            "Remediation verification failed; rollback completed"
        )

    finding["audit_trail"].append({
        "timestamp": ts,
        "actor": actor,
        "action": "rollback_failed",
        "from_status": previous_status,
        "to_status": previous_status,
        "mode": "rollback",
        "remediation_action": plan["action"],
        "applied": False,
        "note": "Original configuration could not be verified after rollback.",
    })

    raise RuntimeError(
        "CRITICAL: remediation verification failed and rollback verification failed"
    )

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Create a safe dry-run remediation plan "
            "for an approved finding."
        )
    )

    parser.add_argument("input_assessment")
    parser.add_argument("output_assessment")
    parser.add_argument("finding_id")
    parser.add_argument("--actor", required=True)
    parser.add_argument("--note", default=None)

    args = parser.parse_args()

    input_path = Path(args.input_assessment)
    output_path = Path(args.output_assessment)

    assessment = json.loads(input_path.read_text())

    result = dry_run_assessment(
        assessment=assessment,
        finding_id=args.finding_id,
        actor=args.actor,
        note=args.note,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, indent=2) + "\n"
    )

    finding = find_finding(result, args.finding_id)

    print(
        f"{args.finding_id}: remediation dry-run "
        f"action={finding['remediation']['plan']['action']} "
        f"applied={finding['remediation']['applied']}"
    )

    print(
        f"DRY-RUN ASSESSMENT CREATED: {output_path}"
    )


if __name__ == "__main__":
    main()
