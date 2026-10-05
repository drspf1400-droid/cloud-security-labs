# 90-Second Interview Pitch

Cloud Security Labs is a Human-Controlled Security Assurance MVP that I built to demonstrate a safer approach to security automation.

The problem I focused on is that scanner findings alone are not enough. Security teams still need prioritization, policy checks, human approval, controlled execution, verification, evidence, and a final decision on whether the environment is safe.

The workflow starts with structured security findings, applies context-aware prioritization and Policy-as-Code guardrails, requires human approval, builds a controlled remediation plan, performs approved remediation, verifies the result, generates execution evidence, produces a Security Assurance report, and evaluates a security gate.

The project also includes signed policy manifests, trusted signer and approver registries, role-aware multi-approver authorization, freshness controls, action-scoped approvals, replay protection, and approval-ledger integrity.

For safety, remediation is disabled by default. The current SSH remediation can execute in the lab environment, while staging and production remain dry-run.

The end-to-end demo safely changes PermitRootLogin from yes to no in an isolated fixture, verifies the remediation, records evidence, and passes the lab security gate.

The current release candidate has 333 passing tests and CI validation through Docker Build Check, Security Checker Test, and Security Assurance Gate.
