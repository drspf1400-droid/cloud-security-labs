#!/usr/bin/env python3

from copy import deepcopy

from modules.approver_trust_registry import (
    verify_rotation_approval_with_registry,
)


class ApprovalQuorumError(ValueError):
    pass


def verify_rotation_approval_quorum(
    plan,
    approvals,
    approver_registry,
    *,
    required_approvals=2,
):
    if (
        not isinstance(required_approvals, int)
        or isinstance(required_approvals, bool)
        or required_approvals < 1
    ):
        raise ApprovalQuorumError(
            "required_approvals must be a positive integer"
        )

    if not isinstance(approvals, list):
        raise ApprovalQuorumError(
            "approvals must be a list"
        )

    results = []
    accepted = []
    rejected = []
    seen_approvers = set()

    for index, approval in enumerate(approvals):
        verification = (
            verify_rotation_approval_with_registry(
                plan,
                approval,
                approver_registry,
            )
        )

        item = deepcopy(verification)
        item["approval_index"] = index

        if not verification.get("valid"):
            rejected.append(item)
            results.append(item)
            continue

        approver_id = (
            verification.get("approved_by")
            or verification.get("approver_id")
        )

        if not approver_id:
            item["valid"] = False
            item["status"] = (
                "missing_approver_identity"
            )

            rejected.append(item)
            results.append(item)
            continue

        if approver_id in seen_approvers:
            item["valid"] = False
            item["status"] = "duplicate_approver"

            rejected.append(item)
            results.append(item)
            continue

        seen_approvers.add(approver_id)

        accepted.append(item)
        results.append(item)

    valid_count = len(accepted)

    quorum_met = (
        valid_count >= required_approvals
    )

    return {
        "valid": quorum_met,
        "status": (
            "quorum_satisfied"
            if quorum_met
            else "quorum_not_satisfied"
        ),
        "required_approvals": required_approvals,
        "valid_approval_count": valid_count,
        "total_approval_count": len(approvals),
        "approvers": [
            item.get("approved_by")
            or item.get("approver_id")
            for item in accepted
        ],
        "accepted_approvals": accepted,
        "rejected_approvals": rejected,
        "verification_results": results,
    }
