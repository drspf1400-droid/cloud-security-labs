# Cloud Security Labs — Portfolio Overview

## Project Positioning

Cloud Security Labs is a Human-Controlled Security Assurance MVP that demonstrates how structured security findings can move through prioritization, policy guardrails, human approval, controlled remediation, verification, evidence generation, reporting, and CI security gates.

The project is intentionally designed around human-controlled and evidence-based security automation rather than zero-touch remediation.

## Problem

Security teams often receive findings from scanners but still need to decide which findings matter, whether remediation is allowed, who approved the action, what changed, whether the change worked, and whether the result is trustworthy.

## Solution

The MVP turns structured findings into a controlled assurance workflow:

Scanner / Structured Findings
→ Context-Aware Prioritization
→ Policy Guardrails
→ Human Approval
→ Controlled Remediation
→ Verification
→ Execution Evidence
→ Security Assurance Report
→ Security Gate

## Key Engineering Capabilities

- JSON Schema validated structured findings
- Context-aware deterministic prioritization
- Policy-as-Code remediation controls
- Human review and approval workflow
- Role-aware multi-approver authorization
- Approval freshness, action scope, and replay protection
- Controlled remediation execution
- Verification and rollback-aware workflows
- SHA-256 execution evidence
- Signed policy manifests and trust registries
- Security Assurance JSON and HTML reporting
- Fail-closed production security gates
- GitHub Actions CI validation

## Safety Model

Remediation is disabled by default and must be explicitly enabled.

The current supported SSH remediation can apply changes in the lab environment, while staging and production remain dry-run and non-destructive.

## Demonstrated Result

The end-to-end demo changes PermitRootLogin from yes to no inside an isolated SSH configuration fixture, verifies the remediation, produces execution evidence, generates an assurance report, and evaluates a security gate.

## Validation

- 333 tests passing
- Docker Build Check passing
- Security Checker Test passing
- Security Assurance Gate passing
- v1.2.0-rc1 published as a GitHub pre-release

## Professional Relevance

This project demonstrates practical security engineering skills across Python, Bash, Linux, Docker, GitHub Actions, Policy-as-Code, secure automation, auditability, trust management, and DevSecOps workflows.
