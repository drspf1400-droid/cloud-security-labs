#!/usr/bin/env python3


def deterministic_mock_analyzer(request):
    finding = request["finding"]
    evidence = finding["evidence"]

    evidence_refs = [
        "finding.evidence",
        "finding.baseline_severity",
    ]

    if finding.get("priority") is not None:
        evidence_refs.append(
            "finding.priority"
        )

    finding_id = finding["finding_id"]

    if (
        finding_id == "SSH-002"
        and evidence.get("type")
        == "configuration"
        and evidence.get("key")
        == "PermitRootLogin"
    ):
        observed = str(
            evidence.get(
                "observed_value",
                "",
            )
        ).lower()

        permitted = observed in {
            "yes",
            "without-password",
            "prohibit-password",
        }

        if permitted:
            return {
                "risk_summary": (
                    "Direct SSH root login is permitted "
                    "and increases administrative risk."
                ),
                "evidence_interpretation": [
                    (
                        "PermitRootLogin is configured "
                        f"as {observed}."
                    ),
                    (
                        "The supplied configuration "
                        "evidence directly supports "
                        "the finding."
                    ),
                ],
                "recommended_action": (
                    "Disable direct SSH root login "
                    "after human review and verify "
                    "the effective SSH configuration."
                ),
                "confidence": 0.95,
                "confidence_basis": [
                    (
                        "The finding is supported by "
                        "explicit configuration evidence."
                    )
                ],
                "priority_recommendation": "keep",
                "evidence_refs": evidence_refs,
                "limitations": [
                    (
                        "External reachability was not "
                        "independently verified."
                    )
                ],
            }

    return {
        "risk_summary": (
            "The finding requires human review "
            "using the supplied evidence."
        ),
        "evidence_interpretation": [
            (
                "Analysis is limited to the evidence "
                "included in the assessment."
            )
        ],
        "recommended_action": (
            "Review the finding and supporting evidence "
            "before approving any remediation."
        ),
        "confidence": 0.60,
        "confidence_basis": [
            (
                "A deterministic fallback analysis "
                "was used."
            )
        ],
        "priority_recommendation": "keep",
        "evidence_refs": evidence_refs,
        "limitations": [
            (
                "No external intelligence or live "
                "system context was used."
            )
        ],
    }
