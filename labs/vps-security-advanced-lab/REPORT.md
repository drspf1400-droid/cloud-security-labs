# Advanced VPS Security Assessment & Hardening Report

## Executive Summary

This lab simulates an intentionally insecure Ubuntu 22.04 VPS and demonstrates a complete security assessment and hardening workflow.

The environment initially allowed direct root SSH login, password-based SSH authentication, and had an inactive host firewall.

The system was then hardened using SSH key-based access, a non-root sudo administrator account, UFW firewall rules, Fail2Ban protection, Nginx reverse proxying, HTTPS/TLS, HTTP-to-HTTPS redirection, and backend service isolation.

The final validation confirmed that all required services remained operational after hardening.

> Note: The security score used in this lab is a custom educational scoring model and is not an official CIS, NIST, or industry certification score.

---

## Lab Environment

- Base OS: Ubuntu 22.04
- Container Runtime: Docker
- SSH Service: OpenSSH
- Reverse Proxy: Nginx
- Intrusion Prevention: Fail2Ban
- Logging: rsyslog
- Firewall: UFW
- TLS: OpenSSL self-signed certificate for lab use
- Backend Service: Python HTTP server

### Docker Host Port Mapping

| Service | Container Port | Host Binding |
|---|---:|---|
| SSH | 22 | 127.0.0.1:2223 |
| HTTP | 80 | 127.0.0.1:8082 |
| HTTPS | 443 | 127.0.0.1:443 |

The backend Python service on port 8080 is not published to the Docker host.

---

## Architecture

```text
Client
   |
   +--> SSH 127.0.0.1:2223
   |
   +--> HTTP 127.0.0.1:8082
   |       |
   |       +--> 301 Redirect
   |               |
   +-----------> HTTPS 127.0.0.1:443
                       |
                     Nginx
                       |
                       v
              127.0.0.1:8080
                 Python Backend
```

---

# Baseline Security Assessment

## Finding 1 — Root SSH Login Enabled

**Severity:** HIGH

**Evidence:** `permitrootlogin yes`

**Risk:** Direct root SSH access increases the impact of credential compromise and exposes a predictable privileged account.

**Remediation:** Disable root SSH login and use a dedicated administrative user with sudo privileges.

## Finding 2 — Password Authentication Enabled

**Severity:** MEDIUM

**Evidence:** `passwordauthentication yes`

**Risk:** Password authentication increases exposure to brute-force and credential-guessing attacks.

**Remediation:** Use SSH public-key authentication and disable password authentication.

## Finding 3 — Host Firewall Inactive

**Severity:** HIGH

**Evidence:** `Status: inactive`

**Risk:** An inactive host firewall can increase the exposed attack surface.

**Remediation:** Enable UFW with a default-deny incoming policy and allow only required services.

## Baseline Positive Controls

- Fail2Ban `sshd` jail active
- Nginx reverse proxy operational
- HTTPS/TLS operational
- HTTP-to-HTTPS redirect operational
- Python backend bound only to `127.0.0.1:8080`
- Backend port 8080 not published to Docker host
- Pending package updates: 0

## Baseline Security Score

```text
Starting Score                    100
Root SSH Login Enabled           -20
Password Authentication Enabled  -20
Firewall Inactive                -25
------------------------------------
Final Baseline Score              35/100
Risk Level                        HIGH
```

> The score above is the custom educational scoring model used by this lab.


---

# Hardening Actions

## 1. Non-Root Administrative Access

A dedicated administrative user named `secadmin` was created and added to the `sudo` group.

Validation:

```text
uid=1000(secadmin) gid=1000(secadmin) groups=1000(secadmin),27(sudo)
```

## 2. SSH Public-Key Authentication

The existing ED25519 public key was installed in:

```text
/home/secadmin/.ssh/authorized_keys
```

Permissions were validated as:

```text
/home/secadmin/.ssh      700
authorized_keys         600
owner                   secadmin:secadmin
```

The private key remained on the WSL host and was never copied into the container.

SSH key login was successfully tested before disabling password authentication.

## 3. Root SSH Login Disabled

Final SSH setting:

```text
permitrootlogin no
```

## 4. Password Authentication Disabled

Final SSH setting:

```text
passwordauthentication no
```

Key-based SSH access for `secadmin` was successfully revalidated after this change.

## 5. UFW Firewall Enabled

Final firewall state:

```text
Status: active
Default: deny (incoming), allow (outgoing), deny (routed)
```

Allowed inbound services:

- 22/tcp — SSH
- 80/tcp — HTTP redirect
- 443/tcp — HTTPS

## 6. Fail2Ban Protection Validated

Fail2Ban was integrated with rsyslog and `/var/log/auth.log`.

Final jail state:

```text
Number of jail: 1
Jail list: sshd
```

Configured thresholds:

```text
maxretry = 5
findtime = 600 seconds
bantime  = 600 seconds
```

A controlled SSH brute-force simulation was performed. Fail2Ban detected repeated authentication failures and successfully banned the source address `172.17.0.1`. The address was then manually unbanned after validation.

## 7. Nginx Reverse Proxy Deployed

Nginx receives web traffic on ports 80 and 443 and proxies HTTPS requests to the backend service on:

```text
127.0.0.1:8080
```

The backend is not published directly to the Docker host.

## 8. HTTPS/TLS Enabled

A self-signed TLS certificate is generated automatically for this lab environment.

Certificate path:

```text
/etc/nginx/ssl/lab.crt
```

Private key path:

```text
/etc/nginx/ssl/lab.key
```

The private key permission was validated as `600`.

For production use, a publicly trusted certificate such as Let's Encrypt should be used instead of the lab self-signed certificate.

## 9. HTTP-to-HTTPS Redirect Enforced

HTTP requests return:

```text
HTTP/1.1 301 Moved Permanently
Location: https://127.0.0.1/
```

HTTPS validation returns:

```text
HTTP/1.1 200 OK
```

## 10. Backend Attack Surface Reduced

The Python backend listens only on:

```text
127.0.0.1:8080
```

Docker port inspection confirmed that port 8080 is not published to the host.


---

# Final Security Validation

## SSH
- Root login: Disabled
- Password authentication: Disabled
- SSH key login for secadmin: PASS

## Firewall
- UFW status: Active
- Default incoming policy: Deny
- Allowed inbound ports: 22, 80, 443

## Fail2Ban
- sshd jail: Active
- Controlled brute-force test: PASS

## Web Security
- HTTP to HTTPS redirect: PASS (301)
- HTTPS response: PASS (200 OK)
- Python backend: 127.0.0.1:8080 only
- Backend port 8080 published to host: No

## Updates
- Pending package updates: 0

---

# Before vs After

| Security Control | Before | After |
|---|---|---|
| Root SSH Login | Enabled | Disabled |
| SSH Password Authentication | Enabled | Disabled |
| Administrative Access | Root | secadmin + sudo |
| SSH Authentication | Password allowed | Key-based |
| UFW Firewall | Inactive | Active |
| Default Incoming Policy | Not enforced | Deny |
| Fail2Ban | Active | Active and validated |
| HTTP | Redirect to HTTPS | Redirect to HTTPS |
| HTTPS | Active | Active |
| Backend Binding | 127.0.0.1:8080 | 127.0.0.1:8080 |
| Backend Host Exposure | Not published | Not published |
| Pending Updates | 0 | 0 |

# Final Security Score

Starting Score: 100
Root SSH Login Enabled: 0 penalty
Password Authentication Enabled: 0 penalty
Firewall Inactive: 0 penalty

**Final Hardened Score: 100/100 — LOW RISK**

> This score is the custom educational scoring model used by this project and is not an official CIS, NIST, or certification score.

# Residual Considerations

- This is a Docker-based security lab, not a full production VPS.
- The TLS certificate is self-signed and intended only for the lab.
- Production systems should use a publicly trusted TLS certificate.
- SSH access should be restricted to trusted management networks where possible.
- Backups, rollback procedures, monitoring, and centralized logging should be used in production.
- Firewall rules and exposed services should be reviewed regularly.

# Conclusion

The Advanced VPS Security Lab demonstrated an end-to-end Linux VPS security assessment and hardening workflow.

The environment progressed from root and password-based SSH access with an inactive firewall to a hardened architecture using a non-root administrator, SSH key authentication, UFW, Fail2Ban, rsyslog, Nginx reverse proxying, HTTPS/TLS, HTTP-to-HTTPS enforcement, backend isolation, and controlled Docker port exposure.

Final validation confirmed that required SSH and web services remained available after hardening.
