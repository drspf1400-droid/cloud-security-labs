[![Docker Build Check](https://github.com/drspf1400-droid/cloud-security-labs/actions/workflows/docker-build.yml/badge.svg)](https://github.com/drspf1400-droid/cloud-security-labs/actions/workflows/docker-build.yml)
[![Security Checker Test](https://github.com/drspf1400-droid/cloud-security-labs/actions/workflows/security-test.yml/badge.svg)](https://github.com/drspf1400-droid/cloud-security-labs/actions/workflows/security-test.yml)
[![Security Assurance Gate](https://github.com/drspf1400-droid/cloud-security-labs/actions/workflows/security-gate.yml/badge.svg)](https://github.com/drspf1400-droid/cloud-security-labs/actions/workflows/security-gate.yml)

# Cloud Security Assurance — Human-Controlled AI Security Automation

A security engineering MVP that transforms structured security findings into
policy-aware, human-controlled remediation decisions using advisory AI,
verification, rollback, execution evidence, and CI security gates.

**Stable release:** `v1.2.0`  
**Validation:** `347 automated tests passing`

## Why This Project Matters

Security automation often moves toward increasingly autonomous remediation.

This project takes a different approach:

> **AI assists analysis. Humans retain control. Policies govern execution. Evidence proves what happened.**

The goal is not zero-touch remediation. The goal is trustworthy security
automation in which important actions remain policy-controlled, attributable,
verifiable, and auditable.

## Security Assurance Workflow

```text
Security Scanner / Structured Findings
              |
              v
Context-Aware Prioritization
              |
              v
Advisory AI Analysis
              |
              v
Policy Guardrails
              |
              v
Human Approval
              |
              v
Controlled Remediation
              |
              v
Verification / Rollback
              |
              v
Execution Evidence
              |
              v
Security Assurance Report
              |
              v
Security Gate
```

## What the MVP Demonstrates

The current MVP combines deterministic security controls with optional
AI-assisted analysis while keeping AI advisory rather than authoritative.

It demonstrates:

- structured security findings and schema validation
- context-aware prioritization
- advisory AI analysis with deterministic mock and local Ollama support
- environment-specific policy guardrails
- explicit human-controlled remediation
- safe-by-default execution
- post-remediation verification
- rollback-aware execution
- execution evidence and auditability
- machine-readable and human-readable assurance reports
- CI-enforced security gates

## Core Capabilities

- Structured findings validated with JSON Schema
- Context-aware deterministic prioritization
- Advisory AI-assisted analysis
- Deterministic mock AI provider
- Local Ollama provider support
- Environment-specific remediation policy
- Human review and approval
- Controlled execution planning
- Explicit opt-in remediation
- Verification after remediation
- Rollback-aware remediation workflow
- SHA-256 execution evidence
- JSON and HTML Security Assurance reports
- Environment-specific security gates
- Signed policy manifests
- Policy integrity verification
- Trusted signer and approver registries
- Role-aware multi-approver quorum
- Approval freshness and action scope
- Replay protection
- Approval usage ledger integrity
- GitHub Actions security validation

## Current Release

**Cloud Security Assurance MVP v1.2.0**

Current validation baseline:

```text
347 passed, 7 warnings
```

Remediation remains disabled by default and production execution is intentionally
non-destructive.

## Safety Model

Remediation is **disabled by default**.

Execution requires explicit operator intent and identity:

```text
--execute-remediation
--actor <identity>
```

The execution engine evaluates approval state, environment policy, execution
context, and verification before considering an action successful.

Current SSH remediation policy:

| Environment | Behavior |
| --- | --- |
| `lab` | Controlled apply |
| `staging` | Dry run |
| `production` | Dry run |

Production remediation is therefore currently non-destructive.

## Quick Start

Install dependencies:

```bash
python3 -m pip install -r requirements-ci.txt
```

Run the safe end-to-end demo:

```bash
./scripts/demo_security_assurance_mvp.sh
```

The demo uses a temporary SSH configuration fixture and does **not** modify the
host `/etc/ssh/sshd_config`.

Expected result:

```text
Before remediation:
PermitRootLogin yes

After remediation:
PermitRootLogin no

Finding status: remediated
Remediation applied: True
Verification passed: True
Security gate: pass
Demo completed successfully.
```

Artifacts are generated under:

```text
/tmp/cloud-security-labs-mvp-demo/output
```

## Run the Test Suite

```bash
python3 -m pytest -q
```

Current baseline:

```text
347 passed, 7 warnings
```

## Run the MVP Directly

Safe, non-destructive pipeline with advisory AI analysis:

```bash
python3 scripts/run_security_assurance_mvp.py \
  --assessment schemas/finding-example.json \
  --trust-report report/trust_decision_report.json \
  --environment lab \
  --enable-ai-analysis \
  --ai-provider mock \
  --output-dir report/mvp \
  --enforce-gate
```

Controlled remediation is explicitly opt-in:

```bash
python3 scripts/run_security_assurance_mvp.py \
  --assessment <assessment.json> \
  --trust-report <trust-report.json> \
  --environment lab \
  --execute-remediation \
  --actor <operator-id> \
  --execution-context <execution-context.json> \
  --output-dir report/mvp \
  --enforce-gate
```

## MVP Output Artifacts

| Artifact | Purpose |
| --- | --- |
| `01_prioritized_assessment.json` | Prioritized findings |
| `ai_analysis_report.json` | Optional advisory AI analysis |
| `02_policy_assessment.json` | Policy decisions |
| `03_execution_plan_assessment.json` | Controlled execution plan |
| `04_execution_assessment.json` | Post-execution assessment |
| `execution_evidence.json` | Execution and integrity evidence |
| `security_assurance_report.json` | Machine-readable assurance report |
| `security_assurance_report.html` | Human-readable assurance report |
| `security_gate_result.json` | Security gate decision |
| `mvp_run_summary.json` | End-to-end run summary |

`04_execution_assessment.json` and `execution_evidence.json` are produced only
when remediation execution is explicitly enabled.

## Linux Security Checker

The original Linux Security Checker remains one input source for the broader
Security Assurance MVP.

It evaluates:

- SSH configuration
- password authentication
- root login
- firewall status
- listening ports
- running services
- package update availability
- system and resource information
- simulated AWS Security Group and IAM conditions

It produces a security score, risk level, recommendations, HTML report, and
structured findings.

Run it with Docker:

```bash
docker build -t linux-security-checker:local .
docker run --rm linux-security-checker:local
```

## Project Structure

```text
modules/     Security, policy, trust, approval, AI, execution, and evidence modules
policies/    Environment-specific security and trust policies
schemas/     Structured security schemas
scripts/     MVP, integrity, reporting, rotation, and demo CLIs
tests/       Unit and end-to-end tests
docs/        Security Assurance MVP documentation
report/      Example and generated security reports
.github/     CI workflows and security-gate automation
```

## CI Security Controls

The repository includes security-focused CI workflows including:

- **Security Checker Test**
- **Docker Build Check**
- **Security Assurance Gate**
- **Production Secure Deployment CI**

The Security Assurance Gate validates the test suite, security policy integrity,
approver registry integrity, passing production decisions, and fail-closed
behavior for unsafe assessments.

## Design Principles

1. Human-controlled
2. Evidence-based
3. Policy-as-code
4. Fail-closed
5. Non-destructive by default
6. Verifiable
7. Auditable
8. AI-assisted, not AI-authoritative

## Documentation

See:

- `docs/security-assurance-mvp.md`
- `SECURITY.md`

## Scope

This is a Security Assurance MVP and security-engineering portfolio project.

It is not a replacement for penetration testing, EDR, SIEM, CSPM, or enterprise
change-management systems.

Automatic remediation coverage is intentionally narrow. The project prioritizes
controlled execution, human approval, verification, and evidence over broad
automatic change coverage.
