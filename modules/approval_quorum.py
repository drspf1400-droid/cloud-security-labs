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
    require_distinct_role_holders=False,
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

    if not isinstance(
        require_distinct_role_holders,
        bool,
    ):
        raise ApprovalQuorumError(
            "require_distinct_role_holders "
            "must be a boolean"
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

    role_candidates = {}

    for role in required_roles:
        role_candidates[role] = [
            (
                item.get("approved_by")
                or item.get("approver_id")
            )
            for item in accepted
            if role in item.get(
                "approver_roles",
                [],
            )
        ]

    role_assignments = {}
    distinct_role_unassigned_roles = []

    if require_distinct_role_holders:
        approver_to_role = {}

        def assign_role(
            role,
            visited,
        ):
            for approver_id in (
                role_candidates[role]
            ):
                if approver_id in visited:
                    continue

                visited.add(
                    approver_id
                )

                previous_role = (
                    approver_to_role.get(
                        approver_id
                    )
                )

                if (
                    previous_role is None
                    or assign_role(
                        previous_role,
                        visited,
                    )
                ):
                    approver_to_role[
                        approver_id
                    ] = role

                    return True

            return False

        for role in required_roles:
            assign_role(
                role,
                set(),
            )

        role_assignments = {
            role: approver_id
            for (
                approver_id,
                role,
            ) in approver_to_role.items()
        }

        distinct_role_unassigned_roles = [
            role
            for role in required_roles
            if role not in role_assignments
        ]

    else:
        for role in required_roles:
            candidates = (
                role_candidates[role]
            )

            if candidates:
                role_assignments[
                    role
                ] = candidates[0]

    distinct_role_holders_satisfied = (
        not distinct_role_unassigned_roles
        if require_distinct_role_holders
        else True
    )

    quorum_met = (
        approval_count_met
        and roles_met
        and distinct_role_holders_satisfied
    )

    if quorum_met:
        status = "quorum_satisfied"

    elif not approval_count_met:
        status = (
            "quorum_not_satisfied"
        )

    elif not roles_met:
        status = (
            "required_roles_not_satisfied"
        )

    else:
        status = (
            "distinct_role_holders_not_satisfied"
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
        "require_distinct_role_holders": (
            require_distinct_role_holders
        ),
        "distinct_role_holders_satisfied": (
            distinct_role_holders_satisfied
        ),
        "role_assignments": (
            role_assignments
        ),
        "distinct_role_unassigned_roles": (
            distinct_role_unassigned_roles
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
