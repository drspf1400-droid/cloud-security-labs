[![Docker Build Check](https://github.com/drspf1400-droid/cloud-security-labs/actions/workflows/docker-build.yml/badge.svg)](https://github.com/drspf1400-droid/cloud-security-labs/actions/workflows/docker-build.yml)

# Linux Security Checker Pro

Linux Security Checker Pro is a Bash-based security auditing tool designed to perform automated baseline security checks on Linux systems.

The tool collects system information, evaluates selected security controls, identifies common security risks, calculates a security score, assigns a risk level, and generates an HTML security report.

## Features

- System information
  - Hostname
  - Current user
  - Kernel version
  - Operating system
  - System uptime

- Resource monitoring
  - CPU usage
  - RAM usage
  - Disk usage

- Security checks
  - Internet connectivity
  - SSH security configuration
  - Firewall status
  - Listening network ports
  - Running services
  - Package update availability

- Security assessment
  - Security findings
  - Severity levels
  - Security score from 0 to 100
  - Risk level
  - Security recommendations

- Reporting
  - Automated HTML security report
  - Audit summary
  - Security findings
  - Security recommendations

## Security Checks

### SSH Security

The checker evaluates SSH configuration for:

- Password authentication
- Root login
- SSH configuration availability

Potential SSH security issues are reported as findings with an appropriate severity level.

### Firewall

The checker evaluates whether UFW is active.

An inactive firewall can result in a high-severity security finding.

### Listening Ports

The checker analyzes listening network sockets and identifies services exposed on public interfaces.

For example:

```text
0.0.0.0:8080
