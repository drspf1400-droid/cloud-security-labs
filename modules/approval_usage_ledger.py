#!/usr/bin/env python3

import hashlib
import json

from copy import deepcopy
from uuid import uuid4

from modules.rotation_approval import (
    parse_timestamp,
)


LEDGER_VERSION = "1.0"

CONSUMPTION_ACTIONS = {
    "execute",
    "promote",
}


class ApprovalUsageLedgerError(ValueError):
    pass


def canonical_approval_artifact_bytes(
    approval,
):
    if not isinstance(approval, dict):
        raise ApprovalUsageLedgerError(
            "approval must be an object"
        )

    return json.dumps(
        approval,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def approval_artifact_fingerprint(
    approval,
):
    return hashlib.sha256(
        canonical_approval_artifact_bytes(
            approval
        )
    ).hexdigest()


def validate_approval_usage_ledger(
    ledger,
):
    if not isinstance(ledger, dict):
        raise ApprovalUsageLedgerError(
            "ledger must be an object"
        )

    if (
        ledger.get("ledger_version")
        != LEDGER_VERSION
    ):
        raise ApprovalUsageLedgerError(
            "unsupported ledger_version"
        )

    if not ledger.get("ledger_id"):
        raise ApprovalUsageLedgerError(
            "ledger_id is required"
        )

    parse_timestamp(
        ledger.get("created_at")
    )

    parse_timestamp(
        ledger.get("updated_at")
    )

    entries = ledger.get(
        "consumed_approvals"
    )

    if not isinstance(entries, list):
        raise ApprovalUsageLedgerError(
            "consumed_approvals must be a list"
        )

    seen_ids = set()
    seen_fingerprints = set()

    required_fields = {
        "approval_id",
        "rotation_id",
        "approval_scope",
        "plan_sha256",
        "approved_by",
        "artifact_sha256",
        "action",
        "consumed_at",
    }

    for entry in entries:
        if not isinstance(entry, dict):
            raise ApprovalUsageLedgerError(
                "ledger entry must be an object"
            )

        missing = (
            required_fields
            - set(entry)
        )

        if missing:
            raise ApprovalUsageLedgerError(
                "ledger entry missing fields: "
                + ", ".join(
                    sorted(missing)
                )
            )

        approval_id = entry[
            "approval_id"
        ]

        if not approval_id:
            raise ApprovalUsageLedgerError(
                "approval_id is required"
            )

        if approval_id in seen_ids:
            raise ApprovalUsageLedgerError(
                "duplicate approval_id in ledger"
            )

        seen_ids.add(
            approval_id
        )

        artifact_sha256 = entry[
            "artifact_sha256"
        ]

        if artifact_sha256 in (
            seen_fingerprints
        ):
            raise ApprovalUsageLedgerError(
                "duplicate approval artifact "
                "in ledger"
            )

        seen_fingerprints.add(
            artifact_sha256
        )

        if (
            entry["action"]
            not in CONSUMPTION_ACTIONS
        ):
            raise ApprovalUsageLedgerError(
                "unsupported consumption action"
            )

        parse_timestamp(
            entry["consumed_at"]
        )

    return True


def create_approval_usage_ledger(
    *,
    created_at,
    ledger_id=None,
):
    parse_timestamp(
        created_at
    )

    if ledger_id is None:
        ledger_id = (
            "APPROVAL-USAGE-LEDGER-"
            + str(uuid4())
        )

    ledger = {
        "ledger_version": (
            LEDGER_VERSION
        ),
        "ledger_id": ledger_id,
        "created_at": created_at,
        "updated_at": created_at,
        "consumed_approvals": [],
    }

    validate_approval_usage_ledger(
        ledger
    )

    return ledger


def evaluate_approval_replay(
    ledger,
    approval,
):
    validate_approval_usage_ledger(
        ledger
    )

    if not isinstance(approval, dict):
        raise ApprovalUsageLedgerError(
            "approval must be an object"
        )

    approval_id = approval.get(
        "approval_id"
    )

    if not approval_id:
        raise ApprovalUsageLedgerError(
            "approval_id is required"
        )

    fingerprint = (
        approval_artifact_fingerprint(
            approval
        )
    )

    for entry in ledger[
        "consumed_approvals"
    ]:
        if (
            entry["approval_id"]
            == approval_id
        ):
            if (
                entry["artifact_sha256"]
                == fingerprint
            ):
                return {
                    "accepted": False,
                    "status": (
                        "approval_replayed"
                    ),
                    "approval_id": (
                        approval_id
                    ),
                    "artifact_sha256": (
                        fingerprint
                    ),
                    "previous_consumption": (
                        deepcopy(entry)
                    ),
                }

            return {
                "accepted": False,
                "status": (
                    "approval_id_collision"
                ),
                "approval_id": (
                    approval_id
                ),
                "artifact_sha256": (
                    fingerprint
                ),
                "previous_consumption": (
                    deepcopy(entry)
                ),
            }

    return {
        "accepted": True,
        "status": "approval_unused",
        "approval_id": approval_id,
        "artifact_sha256": (
            fingerprint
        ),
    }


def consume_approvals(
    ledger,
    approvals,
    *,
    action,
    consumed_at,
):
    validate_approval_usage_ledger(
        ledger
    )

    if not isinstance(approvals, list):
        raise ApprovalUsageLedgerError(
            "approvals must be a list"
        )

    if action not in CONSUMPTION_ACTIONS:
        raise ApprovalUsageLedgerError(
            "unsupported consumption action"
        )

    parse_timestamp(
        consumed_at
    )

    source = deepcopy(
        ledger
    )

    batch_ids = set()

    for approval in approvals:
        if not isinstance(approval, dict):
            raise ApprovalUsageLedgerError(
                "approval must be an object"
            )

        approval_id = approval.get(
            "approval_id"
        )

        if not approval_id:
            raise ApprovalUsageLedgerError(
                "approval_id is required"
            )

        if approval_id in batch_ids:
            raise ApprovalUsageLedgerError(
                "duplicate_approval_in_batch"
            )

        batch_ids.add(
            approval_id
        )

        evaluation = (
            evaluate_approval_replay(
                source,
                approval,
            )
        )

        if not evaluation[
            "accepted"
        ]:
            raise ApprovalUsageLedgerError(
                evaluation["status"]
            )

        required = {
            "rotation_id",
            "plan_sha256",
            "approved_by",
        }

        missing = [
            field
            for field in required
            if not approval.get(field)
        ]

        if missing:
            raise ApprovalUsageLedgerError(
                "approval missing fields: "
                + ", ".join(
                    sorted(missing)
                )
            )

        source[
            "consumed_approvals"
        ].append(
            {
                "approval_id": (
                    approval_id
                ),
                "rotation_id": (
                    approval[
                        "rotation_id"
                    ]
                ),
                "approval_scope": (
                    approval.get(
                        "approval_scope",
                        "rotation",
                    )
                ),
                "plan_sha256": (
                    approval[
                        "plan_sha256"
                    ]
                ),
                "approved_by": (
                    approval[
                        "approved_by"
                    ]
                ),
                "artifact_sha256": (
                    evaluation[
                        "artifact_sha256"
                    ]
                ),
                "action": action,
                "consumed_at": (
                    consumed_at
                ),
            }
        )

    source["updated_at"] = (
        consumed_at
    )

    validate_approval_usage_ledger(
        source
    )

    return source


def canonical_approval_usage_ledger_bytes(
    ledger,
):
    validate_approval_usage_ledger(
        ledger
    )

    return json.dumps(
        ledger,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def approval_usage_ledger_fingerprint(
    ledger,
):
    return hashlib.sha256(
        canonical_approval_usage_ledger_bytes(
            ledger
        )
    ).hexdigest()


def verify_approval_usage_ledger_integrity(
    ledger,
    expected_sha256,
):
    validate_approval_usage_ledger(
        ledger
    )

    if (
        not isinstance(
            expected_sha256,
            str,
        )
        or len(expected_sha256) != 64
    ):
        raise ApprovalUsageLedgerError(
            "expected_sha256 must be a "
            "64-character SHA-256 value"
        )

    try:
        int(expected_sha256, 16)
    except ValueError as exc:
        raise ApprovalUsageLedgerError(
            "expected_sha256 must be hexadecimal"
        ) from exc

    expected = (
        expected_sha256
        .strip()
        .lower()
    )

    actual = (
        approval_usage_ledger_fingerprint(
            ledger
        )
    )

    matches = (
        actual == expected
    )

    return {
        "valid": matches,
        "status": (
            "ledger_integrity_verified"
            if matches
            else "ledger_integrity_mismatch"
        ),
        "expected_sha256": expected,
        "actual_sha256": actual,
        "ledger_id": ledger[
            "ledger_id"
        ],
    }
