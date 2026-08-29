#!/bin/bash

check_updates(){
    echo "[+] Security Updates:"
    echo "Checking package repositories..."

    if ! command -v apt-get >/dev/null 2>&1; then
        echo "APT not available"
        add_finding "MEDIUM | Update check unavailable | APT is not installed | Install/use a supported package manager"
        echo
        return
    fi

    if ! timeout 60s apt-get update -qq >/dev/null 2>&1; then
        echo "Update check unavailable"
        add_finding "LOW | Update check unavailable | Package repository check failed or timed out | Check network/repositories"
        echo
        return
    fi

    UPDATES=$(timeout 10s apt list --upgradable 2>/dev/null | grep -c '\[upgradable from:' || true)

    if [ "$UPDATES" -eq 0 ]; then
        echo "System is up to date"
    else
        echo "$UPDATES package update(s) available"
        add_finding "MEDIUM | Package updates available | $UPDATES update(s) detected | Run apt update && apt upgrade"
    fi

    echo
}
