# LinkedIn Project Description

Cloud Security Labs — Human-Controlled Security Assurance MVP

I built this project to explore a practical question in security automation: how can we automate security workflows without removing human control?

The MVP takes structured security findings through context-aware prioritization, Policy-as-Code guardrails, human approval, controlled remediation, verification, execution evidence, Security Assurance reporting, and security gates.

Key capabilities include role-aware multi-approver authorization, signed policy manifests, trusted signer and approver registries, approval freshness, action-scoped approvals, replay protection, and ledger integrity controls.

The current remediation model is deliberately conservative: execution is disabled by default, supported SSH remediation can run in the lab environment, and staging/production remain dry-run.

The project currently has 333 passing tests, Docker and GitHub Actions validation, a reproducible end-to-end demo, and a published v1.2.0-rc1 pre-release.

Technologies: Python, Bash, Linux, Docker, GitHub Actions, JSON Schema, Policy-as-Code, DevSecOps, security automation, cryptographic integrity, CI/CD security gates.
