import importlib.util
from pathlib import Path


MODULE_PATH = Path("modules/review.py")
spec = importlib.util.spec_from_file_location("review", MODULE_PATH)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


def sample_finding(status="open"):
    return {
        "finding_id": "SSH-002",
        "status": status,
        "remediation": {
            "recommendation": "Disable direct SSH root login.",
            "approval_status": "pending",
            "applied": False,
        },
    }


def test_open_to_under_review():
    finding = sample_finding()

    review.apply_transition(
        finding,
        "under_review",
        actor="tester",
        note="start review",
        timestamp="2026-01-01T00:00:00Z",
    )

    assert finding["status"] == "under_review"
    assert len(finding["audit_trail"]) == 1

    entry = finding["audit_trail"][0]
    assert entry["action"] == "review_started"
    assert entry["from_status"] == "open"
    assert entry["to_status"] == "under_review"


def test_under_review_to_approved():
    finding = sample_finding(status="under_review")

    review.apply_transition(
        finding,
        "approved",
        actor="tester",
        note="approved",
        timestamp="2026-01-01T00:01:00Z",
    )

    assert finding["status"] == "approved"
    assert finding["remediation"]["approval_status"] == "approved"

    human = finding["human_review"]
    assert human["reviewer"] == "tester"
    assert human["decision"] == "approved"
    assert human["reviewed_at"] == "2026-01-01T00:01:00Z"

    entry = finding["audit_trail"][0]
    assert entry["action"] == "approved"


def test_invalid_transition_is_rejected():
    finding = sample_finding()

    try:
        review.apply_transition(
            finding,
            "verified",
            actor="tester",
            timestamp="2026-01-01T00:00:00Z",
        )
    except ValueError as exc:
        assert "Invalid transition" in str(exc)
    else:
        raise AssertionError("Invalid transition was accepted")


def test_risk_acceptance_updates_review():
    finding = sample_finding(status="under_review")

    review.apply_transition(
        finding,
        "accepted",
        actor="tester",
        note="accepted risk",
        timestamp="2026-01-01T00:02:00Z",
    )

    assert finding["status"] == "accepted"
    assert finding["human_review"]["decision"] == "accepted_risk"
    assert finding["remediation"]["approval_status"] == "rejected"


def test_false_positive_updates_review():
    finding = sample_finding(status="under_review")

    review.apply_transition(
        finding,
        "false_positive",
        actor="tester",
        note="not applicable",
        timestamp="2026-01-01T00:03:00Z",
    )

    assert finding["status"] == "false_positive"
    assert finding["human_review"]["decision"] == "false_positive"
    assert finding["remediation"]["approval_status"] == "rejected"
