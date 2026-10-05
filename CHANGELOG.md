# Changelog

All notable changes to this project are documented here.

## [1.2.0-rc1] - 2026-10-05

### Added
- End-to-end Security Assurance MVP orchestrator
- Context-aware prioritization and Policy-as-Code guardrails
- Human review and controlled remediation workflow
- Remediation verification and execution evidence
- JSON and HTML Security Assurance reports
- Environment-specific security gates
- Signed policy manifests and trusted signer registry
- Role-aware multi-approver authorization
- Approval freshness, action scope, and replay protection
- Approval usage ledger with integrity pinning
- One-command safe MVP demo
- Automated MVP integration tests
- Makefile commands for test, demo, and validation

### Security
- Remediation remains disabled by default
- Production remediation is currently dry-run only
- Production security gates fail closed on unsafe assessments
- Human approval is required before supported remediation actions
- Approval trust and replay protections are enforced for sensitive policy rotation workflows

### Documentation
- Repositioned the repository around Human-Controlled Security Assurance
- Added MVP architecture, safety model, quick start, output artifacts, and CI documentation

### Removed
- Removed unused modules/ssh_checke.sh
- Removed tracked project.tar.gz repository snapshot containing Git metadata

### Validation
- 333 tests passing
- Docker Build Check passing
- Security Checker Test passing
- Security Assurance Gate passing

## Earlier Milestones

- v15 - Structured findings and security-assessment evolution
- v14.3 - Earlier Linux Security Checker milestone
- v0.4-risk-assessment - Early risk-assessment milestone
