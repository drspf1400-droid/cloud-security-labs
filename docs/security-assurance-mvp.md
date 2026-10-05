# Security Assurance MVP

The Security Assurance MVP demonstrates a human-controlled,
evidence-based security automation workflow.

## Workflow

Structured Assessment
→ Context-Aware Prioritization
→ Policy Guardrails
→ Human Approval
→ Controlled Remediation
→ Verification
→ Execution Evidence
→ Security Assurance Report
→ Security Gate

## Safety Model

Remediation is disabled by default.

Execution requires the explicit `--execute-remediation` flag
and an actor identity.

The remediation engine enforces human approval,
environment-specific policy, execution context,
verification, and rollback behavior.

Production policy remains non-destructive for the
currently implemented SSH remediation.

## Run the Demo

    ./scripts/demo_security_assurance_mvp.sh

The demo operates only on a temporary SSH configuration
fixture and does not modify the host SSH configuration.

Artifacts are written to:

    /tmp/cloud-security-labs-mvp-demo/output

## Expected Result

Before remediation:

    PermitRootLogin yes

After controlled remediation:

    PermitRootLogin no

The finding becomes `remediated`, execution evidence
receives a SHA-256 integrity hash, and the security gate
produces a machine-readable decision.

## Design Principle

This project does not implement zero-touch remediation.

Automation operates within policy while preserving
human control, verification, rollback, and auditable evidence.
