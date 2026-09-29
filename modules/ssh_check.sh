#!/bin/bash

check_ssh() {
    echo "[+] SSH Security:"

    mkdir -p /run/sshd
    ssh-keygen -A >/dev/null 2>&1

    if ! sshd -t >/dev/null 2>&1; then
        echo "Unable to read SSH configuration"
        add_finding "HIGH | SSH configuration could not be evaluated | Check sshd_config"
        return
    fi

    SSH_CONFIG=$(sshd -T 2>/dev/null)

    if echo "$SSH_CONFIG" | grep -q "^passwordauthentication yes"; then
        echo "Password Authentication: ENABLED"

        add_finding "MEDIUM | SSH password authentication enabled | Disable password login | /etc/ssh/sshd_config"

        add_structured_finding \
            "SSH-001" \
            "ssh" \
            "SSH password authentication enabled" \
            "MEDIUM" \
            "linux_configuration" \
            "ssh_check" \
            "configuration" \
            "/etc/ssh/sshd_config" \
            "PasswordAuthentication" \
            "yes" \
            "Disable SSH password authentication and use key-based authentication."
    else
        echo "Password Authentication: DISABLED"
    fi

    if echo "$SSH_CONFIG" | grep -Eq "^permitrootlogin (yes|without-password)"; then
        ROOT_LOGIN_VALUE=$(echo "$SSH_CONFIG" | awk '/^permitrootlogin / {print $2; exit}')

        echo "Root Login: ENABLED"

        add_finding "HIGH | SSH root login enabled | Disable root login | /etc/ssh/sshd_config"

        add_structured_finding \
            "SSH-002" \
            "ssh" \
            "SSH root login enabled" \
            "HIGH" \
            "linux_configuration" \
            "ssh_check" \
            "configuration" \
            "/etc/ssh/sshd_config" \
            "PermitRootLogin" \
            "$ROOT_LOGIN_VALUE" \
            "Disable direct SSH root login."
    else
        echo "Root Login: DISABLED"
    fi
}
