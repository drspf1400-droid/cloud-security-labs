#!/bin/bash

check_ports(){
    echo "[+] Listening Ports:"

    PORTS=$(ss -lntupH 2>/dev/null)

    if [ -z "$PORTS" ]; then
        echo "No listening TCP ports detected"
        echo
        return
    fi

    echo "$PORTS"

    while read -r proto state recvq sendq local peer process; do
        port="${local##*:}"

        if [[ "$local" == 0.0.0.0:* || "$local" == \[::\]:* ]]; then
            if [[ "$port" != "22" ]]; then
                add_finding "MEDIUM | Publicly exposed port detected | $local | Review firewall/service configuration"
            fi
        fi
    done <<< "$PORTS"

    echo
}
