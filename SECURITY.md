# Security Policy

## Overview

Linux Security Checker Pro is a Bash-based security auditing tool designed to perform automated baseline security checks on Linux systems.

The project is intended for security assessment, learning, testing, and demonstration purposes.

## Supported Versions

| Version | Supported |
| --- | --- |
| Latest version on `main` | Yes |
| Older versions | No |

Security fixes and improvements are applied to the latest version of the project.

## Security Checks

The checker currently evaluates several baseline security controls, including:

- SSH configuration
- Password authentication
- SSH root login
- Firewall status
- Listening network ports
- Running services
- Package update availability
- System and resource information

The checker calculates a security score from 0 to 100 and assigns a risk level based on detected findings.

## Limitations

This tool performs baseline security checks and should not be considered a complete security assessment.

It does not replace:

- Professional penetration testing
- Vulnerability scanners
- Endpoint security solutions
- SIEM platforms
- Cloud security posture management tools
- Manual security reviews

Some checks may behave differently inside Docker containers because containers do not normally run a complete init system.

For the most accurate results, running the checker directly on the target Linux host is recommended.

## Reporting a Security Issue

If you discover a security vulnerability in this project, please report it responsibly.

Do not publicly disclose sensitive vulnerability details before the issue has been reviewed.

When reporting a security issue, include:

- A clear description of the issue
- Steps to reproduce it
- Affected file or component
- Expected behavior
- Actual behavior
- Potential security impact

## Responsible Disclosure

Please allow reasonable time for investigation and remediation before publicly disclosing a vulnerability.

Security reports should contain only the information necessary to reproduce and understand the issue.

## Security Disclaimer

This project is provided for educational, testing, and security-auditing purposes.

The authors are not responsible for damage, data loss, service interruption, or other consequences resulting from the use or misuse of this tool.

Always test security changes in an appropriate environment before applying them to production systems.
