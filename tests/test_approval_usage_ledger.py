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


def test_ledger_fingerprint_is_deterministic():
    from modules.approval_usage_ledger import (
        approval_usage_ledger_fingerprint,
    )

    ledger = build_ledger()

    first = (
        approval_usage_ledger_fingerprint(
            ledger
        )
    )

    reordered = {
        "consumed_approvals": (
            ledger[
                "consumed_approvals"
            ]
        ),
        "updated_at": (
            ledger["updated_at"]
        ),
        "created_at": (
            ledger["created_at"]
        ),
        "ledger_id": (
            ledger["ledger_id"]
        ),
        "ledger_version": (
            ledger["ledger_version"]
        ),
    }

    second = (
        approval_usage_ledger_fingerprint(
            reordered
        )
    )

    assert first == second
    assert len(first) == 64


def test_ledger_fingerprint_changes_after_consumption():
    from modules.approval_usage_ledger import (
        approval_usage_ledger_fingerprint,
    )

    ledger = build_ledger()

    before = (
        approval_usage_ledger_fingerprint(
            ledger
        )
    )

    updated = consume_approvals(
        ledger,
        [sample_approval()],
        action="execute",
        consumed_at=CONSUMED_AT,
    )

    after = (
        approval_usage_ledger_fingerprint(
            updated
        )
    )

    assert before != after


def test_ledger_integrity_accepts_matching_pin():
    from modules.approval_usage_ledger import (
        approval_usage_ledger_fingerprint,
        verify_approval_usage_ledger_integrity,
    )

    ledger = build_ledger()

    fingerprint = (
        approval_usage_ledger_fingerprint(
            ledger
        )
    )

    result = (
        verify_approval_usage_ledger_integrity(
            ledger,
            fingerprint,
        )
    )

    assert result["valid"] is True

    assert (
        result["status"]
        == "ledger_integrity_verified"
    )


def test_ledger_integrity_rejects_wrong_pin():
    from modules.approval_usage_ledger import (
        verify_approval_usage_ledger_integrity,
    )

    result = (
        verify_approval_usage_ledger_integrity(
            build_ledger(),
            "0" * 64,
        )
    )

    assert result["valid"] is False

    assert (
        result["status"]
        == "ledger_integrity_mismatch"
    )


def test_ledger_integrity_rejects_invalid_pin():
    from modules.approval_usage_ledger import (
        ApprovalUsageLedgerError,
        verify_approval_usage_ledger_integrity,
    )

    with pytest.raises(
        ApprovalUsageLedgerError
    ):
        verify_approval_usage_ledger_integrity(
            build_ledger(),
            "not-a-sha256",
        )
