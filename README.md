# Linux Security Checker Pro

Linux Security Checker Pro is a Bash-based security auditing tool designed to perform basic security and system checks on Linux servers.

## Features

- System information
- CPU usage
- RAM usage
- Disk usage
- Internet connectivity status
- SSH service status
- Firewall status
- Security score
- Basic security recommendations

## Requirements

- Ubuntu 20.04 or later
- Bash
- Standard Linux command-line tools

## Usage

First, make the script executable:

```bash
chmod +x checker.sh

## Running with Docker

You can run this security checker in an isolated container without installing anything on your host system:

```bash
docker build -t linux-security-checker .
docker run linux-security-checker
```

**Note:** Some checks (like `systemctl`-based service detection) behave differently inside a container since containers don't run a full init system. The Dockerfile includes lightweight compatibility shims so the script runs cleanly, but for full accuracy, running directly on a host is recommended.
