from copy import deepcopy

import pytest

from modules.approval_usage_ledger import (
    ApprovalUsageLedgerError,
    approval_artifact_fingerprint,
    consume_approvals,
    create_approval_usage_ledger,
    evaluate_approval_replay,
)


CREATED_AT = (
    "2026-10-04T08:00:00+00:00"
)

CONSUMED_AT = (
    "2026-10-04T10:00:00+00:00"
)


def sample_approval():
    return {
        "approval_version": "1.0",
        "approval_id": "APPROVAL-001",
        "approval_scope": "execute",
        "rotation_id": "ROTATION-001",
        "plan_sha256": "a" * 64,
        "decision": "approved",
        "initiated_by": "operator",
        "approved_by": "security-admin",
        "approved_at": (
            "2026-10-04T09:30:00+00:00"
        ),
        "approver_key": {
            "algorithm": "ed25519",
            "key_fingerprint": "b" * 64,
            "public_key_b64": "example",
        },
        "signature": {
            "algorithm": "ed25519",
            "value": "example-signature",
        },
    }


def build_ledger():
    return create_approval_usage_ledger(
        created_at=CREATED_AT,
        ledger_id=(
            "APPROVAL-USAGE-LEDGER-001"
        ),
    )


def test_new_ledger_is_empty():
    ledger = build_ledger()

    assert (
        ledger["ledger_version"]
        == "1.0"
    )

    assert (
        ledger["consumed_approvals"]
        == []
    )


def test_consumed_approval_is_recorded():
    ledger = build_ledger()
    approval = sample_approval()

    result = consume_approvals(
        ledger,
        [approval],
        action="execute",
        consumed_at=CONSUMED_AT,
    )

    assert (
        len(
            result[
                "consumed_approvals"
            ]
        )
        == 1
    )

    entry = result[
        "consumed_approvals"
    ][0]

    assert (
        entry["approval_id"]
        == "APPROVAL-001"
    )

    assert (
        entry["action"]
        == "execute"
    )

    assert (
        entry["artifact_sha256"]
        == approval_artifact_fingerprint(
            approval
        )
    )


def test_replayed_approval_is_rejected():
    approval = sample_approval()

    ledger = consume_approvals(
        build_ledger(),
        [approval],
        action="execute",
        consumed_at=CONSUMED_AT,
    )

    replay = evaluate_approval_replay(
        ledger,
        approval,
    )

    assert replay["accepted"] is False

    assert (
        replay["status"]
        == "approval_replayed"
    )


def test_same_approval_id_with_different_artifact_is_collision():
    approval = sample_approval()

    ledger = consume_approvals(
        build_ledger(),
        [approval],
        action="execute",
        consumed_at=CONSUMED_AT,
    )

    modified = deepcopy(
        approval
    )

    modified["approved_by"] = (
        "platform-owner"
    )

    result = evaluate_approval_replay(
        ledger,
        modified,
    )

    assert result["accepted"] is False

    assert (
        result["status"]
        == "approval_id_collision"
    )


def test_duplicate_approval_in_same_batch_is_rejected():
    approval = sample_approval()

    with pytest.raises(
        ApprovalUsageLedgerError,
        match="duplicate_approval_in_batch",
    ):
        consume_approvals(
            build_ledger(),
            [
                approval,
                deepcopy(approval),
            ],
            action="execute",
            consumed_at=CONSUMED_AT,
        )


def test_consumption_does_not_mutate_inputs():
    ledger = build_ledger()
    approval = sample_approval()

    original_ledger = deepcopy(
        ledger
    )

    original_approval = deepcopy(
        approval
    )

    consume_approvals(
        ledger,
        [approval],
        action="execute",
        consumed_at=CONSUMED_AT,
    )

    assert ledger == original_ledger
    assert approval == original_approval


def test_naive_consumption_timestamp_is_rejected():
    with pytest.raises(Exception):
        consume_approvals(
            build_ledger(),
            [sample_approval()],
            action="execute",
            consumed_at=(
                "2026-10-04T10:00:00"
            ),
        )
