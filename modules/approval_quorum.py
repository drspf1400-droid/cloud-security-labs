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
    required_roles=None,
):
    """
    Verify independently signed approvals.

    Quorum rules:
    - only valid trusted approvals count
    - each approver_id counts once
    - required_approvals must be satisfied
    - every required role must be represented
      by at least one accepted approver
    """

    if (
        not isinstance(
            required_approvals,
            int,
        )
        or isinstance(
            required_approvals,
            bool,
        )
        or required_approvals < 1
    ):
        raise ApprovalQuorumError(
            "required_approvals must be "
            "a positive integer"
        )

    if not isinstance(
        approvals,
        list,
    ):
        raise ApprovalQuorumError(
            "approvals must be a list"
        )

    if required_roles is None:
        required_roles = []

    if not isinstance(
        required_roles,
        list,
    ):
        raise ApprovalQuorumError(
            "required_roles must be a list"
        )

    if not all(
        isinstance(role, str)
        and role
        for role in required_roles
    ):
        raise ApprovalQuorumError(
            "required_roles must contain "
            "non-empty strings"
        )

    if (
        len(set(required_roles))
        != len(required_roles)
    ):
        raise ApprovalQuorumError(
            "required_roles must be unique"
        )

    results = []
    accepted = []
    rejected = []

    seen_approvers = set()
    satisfied_roles = set()

    for index, approval in enumerate(
        approvals
    ):
        verification = (
            verify_rotation_approval_with_registry(
                plan,
                approval,
                approver_registry,
            )
        )

        item = deepcopy(
            verification
        )

        item["approval_index"] = index

        if not verification.get(
            "valid"
        ):
            rejected.append(
                item
            )
            results.append(
                item
            )
            continue

        approver_id = (
            verification.get(
                "approved_by"
            )
            or verification.get(
                "approver_id"
            )
        )

        if not approver_id:
            item["valid"] = False
            item["status"] = (
                "missing_approver_identity"
            )

            rejected.append(
                item
            )
            results.append(
                item
            )
            continue

        if approver_id in seen_approvers:
            item["valid"] = False
            item["status"] = (
                "duplicate_approver"
            )

            rejected.append(
                item
            )
            results.append(
                item
            )
            continue

        seen_approvers.add(
            approver_id
        )

        satisfied_roles.update(
            verification.get(
                "approver_roles",
                [],
            )
        )

        accepted.append(
            item
        )

        results.append(
            item
        )

    valid_count = len(
        accepted
    )

    approval_count_met = (
        valid_count
        >= required_approvals
    )

    missing_roles = sorted(
        set(required_roles)
        - satisfied_roles
    )

    roles_met = not missing_roles

    quorum_met = (
        approval_count_met
        and roles_met
    )

    if quorum_met:
        status = "quorum_satisfied"

    elif not approval_count_met:
        status = (
            "quorum_not_satisfied"
        )

    else:
        status = (
            "required_roles_not_satisfied"
        )

    return {
        "valid": quorum_met,
        "status": status,
        "required_approvals": (
            required_approvals
        ),
        "required_roles": list(
            required_roles
        ),
        "satisfied_roles": sorted(
            satisfied_roles
        ),
        "missing_roles": (
            missing_roles
        ),
        "valid_approval_count": (
            valid_count
        ),
        "total_approval_count": (
            len(approvals)
        ),
        "approvers": [
            item.get(
                "approved_by"
            )
            or item.get(
                "approver_id"
            )
            for item in accepted
        ],
        "accepted_approvals": (
            accepted
        ),
        "rejected_approvals": (
            rejected
        ),
        "verification_results": (
            results
        ),
    }
