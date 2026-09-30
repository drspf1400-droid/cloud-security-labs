#!/usr/bin/env python3

from copy import deepcopy
from datetime import datetime, timezone
from uuid import uuid4

try:
    from modules.trusted_signers import (
        evaluate_manifest_trust,
    )
except ModuleNotFoundError:
    from trusted_signers import (
        evaluate_manifest_trust,
    )


REPORT_VERSION = "1.0"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def build_trust_decision_report(
    manifest,
    registry,
    *,
    report_id=None,
    generated_at=None,
):
    """
    Build a structured trust-decision report without
    mutating the manifest or signer registry.
    """
    manifest_copy = deepcopy(manifest)
    registry_copy = deepcopy(registry)

    if report_id is None:
        report_id = str(uuid4())

    if generated_at is None:
        generated_at = utc_now()

    trust = evaluate_manifest_trust(
        manifest_copy,
        registry_copy,
    )

    fingerprint = trust.get(
        "key_fingerprint"
    )

    lifecycle = trust.get(
        "signer_lifecycle",
        {},
    )

    signer = lifecycle.get(
        "signer"
    ) or {}

    current = trust.get(
        "current_trust",
        {},
    )

    historical = trust.get(
        "historical_trust",
        {},
    )

    effective = trust.get(
        "effective_trust",
        {},
    )

    effective_decision = (
        "accept"
        if effective.get("accepted")
        else "reject"
    )

    return {
        "report_version": REPORT_VERSION,
        "report_id": report_id,
        "generated_at": generated_at,
        "manifest": {
            "run_id": manifest_copy.get("run_id"),
            "created_at": manifest_copy.get("created_at"),
            "actor": manifest_copy.get("actor"),
            "environment": manifest_copy.get(
                "environment"
            ),
        },
        "signer": {
            "signer_id": signer.get("signer_id"),
            "key_id": signer.get("key_id"),
            "key_fingerprint": fingerprint,
            "key_status": signer.get("status"),
            "registered_at": signer.get(
                "registered_at"
            ),
            "revoked_at": signer.get(
                "revoked_at"
            ),
            "revocation_reason": signer.get(
                "revocation_reason"
            ),
        },
        "verification": {
            "signature_valid": (
                historical.get(
                    "signature_valid",
                    current.get(
                        "signature_valid",
                        False,
                    ),
                )
            ),
            "current_trust": {
                "accepted": current.get(
                    "accepted",
                    False,
                ),
                "status": current.get("status"),
                "reason": current.get("reason"),
            },
            "historical_trust": {
                "accepted": historical.get(
                    "accepted",
                    False,
                ),
                "status": historical.get(
                    "status"
                ),
                "reason": historical.get(
                    "reason"
                ),
            },
            "effective_decision": (
                effective_decision
            ),
            "decision_basis": effective.get(
                "basis"
            ),
            "decision_reason": effective.get(
                "reason"
            ),
        },
        "lifecycle_audit": deepcopy(
            lifecycle.get(
                "audit_events",
                [],
            )
        ),
    }
