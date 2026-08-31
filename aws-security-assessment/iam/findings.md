# AWS IAM Security Findings

## IAM-001 - Excessive IAM Permissions

Severity: HIGH

Category: IAM / Least Privilege

Description:
An IAM identity has permissions broader than required for its intended role.

Risk:
- Unauthorized access
- Privilege escalation
- Data exposure
- Accidental destructive actions

Evidence:
The policy contains wildcard permissions:

Action: *
Resource: *

Recommendation:
Apply the principle of least privilege.

Remediation:
1. Review attached IAM policies.
2. Remove unnecessary permissions.
3. Replace wildcard permissions with specific permissions.
4. Review permissions periodically.
