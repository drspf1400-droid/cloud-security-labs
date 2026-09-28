#!/usr/bin/env python3

import argparse
import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path


ALLOWED_TRANSITIONS = {
    ("open", "under_review"): "review_started",
    ("under_review", "approved"): "approved",
    ("under_review", "open"): "rejected",
    ("under_review", "accepted"): "risk_accepted",
    ("under_review", "false_positive"): "marked_false_positive",
}


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def find_finding(assessment, finding_id):
    for finding in assessment["findings"]:
        if finding["finding_id"] == finding_id:
            return finding

    raise ValueError(f"Finding not found: {finding_id}")


def apply_transition(
    finding,
    to_status,
    actor,
    note=None,
    timestamp=None,
):
    current_status = finding["status"]
    transition = (current_status, to_status)

    if transition not in ALLOWED_TRANSITIONS:
        raise ValueError(
            f"Invalid transition: {current_status} -> {to_status}"
        )

    action = ALLOWED_TRANSITIONS[transition]
    ts = timestamp or utc_now()

    finding.setdefault("audit_trail", [])

    finding["audit_trail"].append({
        "timestamp": ts,
        "actor": actor,
        "action": action,
        "from_status": current_status,
        "to_status": to_status,
        "note": note,
    })

    finding["status"] = to_status

    if to_status == "approved":
        finding["human_review"] = {
            "reviewer": actor,
            "decision": "approved",
            "reviewed_at": ts,
            "note": note,
        }

        finding["remediation"]["approval_status"] = "approved"

    elif to_status == "accepted":
        finding["human_review"] = {
            "reviewer": actor,
            "decision": "accepted_risk",
            "reviewed_at": ts,
            "note": note,
        }

        finding["remediation"]["approval_status"] = "rejected"

    elif to_status == "false_positive":
        finding["human_review"] = {
            "reviewer": actor,
            "decision": "false_positive",
            "reviewed_at": ts,
            "note": note,
        }

        finding["remediation"]["approval_status"] = "rejected"

    return finding


def review_assessment(
    assessment,
    finding_id,
    to_status,
    actor,
    note=None,
):
    result = deepcopy(assessment)

    finding = find_finding(result, finding_id)

    apply_transition(
        finding=finding,
        to_status=to_status,
        actor=actor,
        note=note,
    )

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Apply a human-review status transition to a finding."
    )

    parser.add_argument("input_assessment")
    parser.add_argument("output_assessment")
    parser.add_argument("finding_id")
    parser.add_argument("to_status")
    parser.add_argument("--actor", required=True)
    parser.add_argument("--note", default=None)

    args = parser.parse_args()

    input_path = Path(args.input_assessment)
    output_path = Path(args.output_assessment)

    assessment = json.loads(input_path.read_text())

    result = review_assessment(
        assessment=assessment,
        finding_id=args.finding_id,
        to_status=args.to_status,
        actor=args.actor,
        note=args.note,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, indent=2) + "\n"
    )

    finding = find_finding(result, args.finding_id)

    print(
        f"{args.finding_id}: "
        f"{finding['audit_trail'][-1]['from_status']} "
        f"-> {finding['status']}"
    )

    print(
        f"REVIEWED ASSESSMENT CREATED: {output_path}"
    )


if __name__ == "__main__":
    main()
