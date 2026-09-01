# VPS Security Assessment & Hardening Report

## 1. Executive Summary

A security assessment was performed against a deliberately insecure Ubuntu 22.04 VPS lab environment.

The objective was to identify common Linux server security weaknesses, apply appropriate hardening controls, and verify the effectiveness of the remediation.

The initial assessment identified five security issues, including insecure SSH authentication, unrestricted root SSH access, an inactive firewall, an exposed application service, and missing package updates.

Following remediation, secure SSH key authentication was implemented, root and password-based SSH access were disabled, the firewall was enabled, unnecessary network exposure was restricted, and available system updates were installed.

### Overall Result

| Metric                  | Before Hardening | After Hardening |
| ----------------------- | ---------------: | --------------: |
| Security Score          |           10/100 |        100/100* |
| Risk Level              |             HIGH |             LOW |
| Root SSH Login          |          Enabled |        Disabled |
| Password SSH Login      |          Enabled |        Disabled |
| SSH Key Authentication  |   Not configured |         Enabled |
| Firewall                |         Inactive |          Active |
| TCP/8080 Reachability   |        Reachable |         Blocked |
| Pending Package Updates |               18 |               0 |

*The final score is based on effective external exposure. The application on TCP/8080 remains listening internally on `0.0.0.0`, but inbound access is blocked by the firewall.

---

## 2. Assessment Environment

* Operating System: Ubuntu 22.04
* Environment: Docker-based simulated VPS
* SSH Service: OpenSSH
* Test SSH Port on Host: 2222
* Application Port: TCP/8080
* Firewall: UFW
* Administrative User Created: `secadmin`
* Authentication Method After Hardening: ED25519 SSH key

The Docker environment was intentionally configured with insecure settings to simulate a real-world misconfigured Linux VPS.

The host exposed the lab services only through `127.0.0.1` for safe local testing.

---

## 3. Initial Security Findings

### FINDING-01 — Publicly Exposed Application Service

**Severity:** MEDIUM

**Evidence:**

```text
LISTEN 0 5 0.0.0.0:8080 0.0.0.0:*
```

A Python HTTP application was listening on TCP/8080 on all network interfaces.

### Risk

Services listening on all interfaces may become accessible from untrusted networks if network controls are not correctly configured.

### Remediation

Enable host firewall protection and permit only explicitly required inbound services.

---

### FINDING-02 — SSH Root Login Enabled

**Severity:** HIGH

**Evidence:**

```text
permitrootlogin yes
```

Direct SSH login as the root user was permitted.

### Risk

Allowing direct root authentication increases the impact of credential compromise and exposes the highest-privileged account directly to authentication attacks.

### Remediation

Create a separate administrative account and disable direct root SSH login.

---

### FINDING-03 — SSH Password Authentication Enabled

**Severity:** MEDIUM

**Evidence:**

```text
passwordauthentication yes
```

SSH accepted password-based authentication.

### Risk

Password authentication increases exposure to password guessing, brute-force attacks, and credential reuse attacks.

### Remediation

Configure SSH public-key authentication and disable password authentication after successful key-based access has been verified.

---

### FINDING-04 — Firewall Inactive

**Severity:** HIGH

**Evidence:**

```text
Status: inactive
```

The UFW firewall was installed but not active.

### Risk

Without an active host firewall, services listening on network interfaces may be exposed unnecessarily.

### Remediation

Enable UFW using a deny-by-default inbound policy and allow only required services.

---

### FINDING-05 — Package Updates Available

**Severity:** MEDIUM

**Evidence:**

```text
18 package updates available
```

Multiple Ubuntu packages, including security-related packages, were outdated.

### Risk

Outdated software may contain known vulnerabilities that have already been corrected by vendor security updates.

### Remediation

Update package repositories and install available operating-system updates.

---

## 4. Initial Risk Assessment

The initial assessment produced the following score:

```text
Starting Score                 100
SSH Password Authentication   -20
SSH Root Login                -20
Inactive Firewall             -25
Public Application Port       -15
Available Updates             -10
---------------------------------
Final Score                    10/100
Risk Level                     HIGH
```

---

## 5. Hardening Actions Performed

### 5.1 Created a Non-Root Administrative User

A dedicated administrative account named `secadmin` was created.

The account was added to the `sudo` group.

Verification:

```text
uid=1000(secadmin)
gid=1000(secadmin)
groups=1000(secadmin),27(sudo)
```

---

## 5.2 Configured SSH Public-Key Authentication

An ED25519 SSH key pair was generated for administrative access.

The public key was installed in:

```text
/home/secadmin/.ssh/authorized_keys
```

Secure permissions were applied:

```text
.ssh             700
authorized_keys  600
```

Key-based login was successfully tested before disabling existing authentication methods.

Verification:

```text
secadmin
uid=1000(secadmin) gid=1000(secadmin) groups=1000(secadmin),27(sudo)
```

---

## 5.3 Disabled SSH Root Login

The SSH configuration was changed from:

```text
PermitRootLogin yes
```

to:

```text
PermitRootLogin no
```

Post-hardening verification:

```text
permitrootlogin no
```

---

## 5.4 Disabled SSH Password Authentication

Password authentication was changed from:

```text
PasswordAuthentication yes
```

to:

```text
PasswordAuthentication no
```

Post-hardening verification:

```text
passwordauthentication no
```

Administrative access continued to work successfully using the SSH key.

---

## 5.5 Enabled and Configured UFW

The firewall was configured with the following security policy:

```text
Default incoming: deny
Default outgoing: allow
```

Only SSH was explicitly permitted:

```text
22/tcp ALLOW
```

Final firewall status:

```text
Status: active

22/tcp      ALLOW       Anywhere
22/tcp (v6) ALLOW       Anywhere (v6)
```

---

## 5.6 Restricted Access to TCP/8080

The application continued listening internally on:

```text
0.0.0.0:8080
```

However, no UFW allow rule was created for TCP/8080.

External reachability testing produced:

```text
curl: (28) Operation timed out after 5000 milliseconds with 0 bytes received
```

This confirmed that inbound access to the application was blocked by the firewall.

### Residual Observation

The application process still binds to all interfaces internally.

For a production environment, an additional hardening option would be to bind the service only to localhost or a private interface when public network access is not required.

---

## 5.7 Installed Available Package Updates

Before remediation:

```text
18 packages upgradable
```

After applying system updates:

```text
0 packages upgradable
```

All detected pending package updates were successfully installed.

---

## 6. Post-Hardening Validation

### SSH Configuration

```text
permitrootlogin no
passwordauthentication no
```

### Firewall

```text
Status: active
22/tcp ALLOW Anywhere
```

### Package Updates

```text
0
```

### SSH Key Authentication

```text
secadmin
```

Key-based administrative SSH access remained functional after the security changes.

### Application Exposure Test

```text
curl --max-time 5 http://127.0.0.1:8080
curl: (28) Operation timed out after 5000 milliseconds with 0 bytes received
```

The application was no longer reachable through the tested inbound path.

---

## 7. Before vs. After

| Security Control        | Before         | After      |
| ----------------------- | -------------- | ---------- |
| Root SSH Login          | Enabled        | Disabled   |
| Password Authentication | Enabled        | Disabled   |
| SSH Key Authentication  | Not configured | Enabled    |
| Administrative User     | Root           | `secadmin` |
| Firewall                | Inactive       | Active     |
| Default Incoming Policy | Unrestricted   | Deny       |
| SSH Firewall Rule       | None           | Allowed    |
| TCP/8080 Access         | Reachable      | Blocked    |
| Pending Updates         | 18             | 0          |
| Risk Level              | HIGH           | LOW        |

---

## 8. Final Security Status

After remediation, all identified security findings were either resolved or effectively mitigated.

```text
Before Hardening
Security Score: 10/100
Risk Level: HIGH

After Hardening
Security Score: 100/100
Risk Level: LOW
```

One residual observation remains:

```text
TCP/8080 continues to listen on 0.0.0.0 internally.
```

The service is protected by the firewall, but binding the application to a more restrictive network interface would provide additional defense in depth.

---

## 9. Recommendations for Production Environments

For production Linux servers, additional security controls should also be considered:

* Configure Fail2Ban or equivalent brute-force protection.
* Enable automatic security updates where appropriate.
* Review unnecessary services regularly.
* Restrict administrative access by trusted IP ranges when possible.
* Implement centralized logging and monitoring.
* Configure secure backups and periodically test recovery.
* Monitor authentication logs for suspicious activity.
* Use least-privilege administrative accounts.
* Review exposed Docker/container ports.
* Protect secrets, environment files, and API credentials.
* Periodically repeat the security assessment.

---

## 10. Conclusion

The assessment demonstrated a complete security-hardening workflow:

```text
Initial Assessment
        ↓
Security Findings
        ↓
Risk Evaluation
        ↓
Remediation
        ↓
Validation
        ↓
Re-Assessment
        ↓
Before / After Security Report
```

The lab demonstrates practical experience with Linux security assessment, SSH hardening, firewall configuration, network exposure analysis, patch management, remediation validation, and security reporting.

---

**Project:** Linux VPS Security Assessment & Hardening Lab
**Purpose:** Security Engineering Portfolio / Training Environment
**Environment:** Ubuntu 22.04 / Docker
**Assessment Type:** Baseline Infrastructure Security Assessment
