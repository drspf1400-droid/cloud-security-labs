#!/bin/bash

check_ports(){
    echo "[+] Listening Ports:"

    PORTS=$(ss -lntupH 2>/dev/null)

    if [ -z "$PORTS" ]; then
        echo "No listening TCP/UDP ports detected"
        echo
        return
    fi

    echo "$PORTS"

    while read -r proto state recvq sendq local peer process; do
        port="${local##*:}"
        bind_address="${local%:*}"
        bind_address="${bind_address#[}"
        bind_address="${bind_address%]}"

        if [[ "$local" == 0.0.0.0:* || "$local" == \[::\]:* ]]; then
            if [[ "$port" != "22" && "$port" =~ ^[0-9]+$ ]]; then
                add_finding "MEDIUM | Publicly bound port detected | $local | Review firewall/service configuration"

                add_socket_finding \
                    "NET-$port" \
                    "network" \
                    "Publicly bound listening socket detected" \
                    "MEDIUM" \
                    "ports_check" \
                    "$proto" \
                    "$bind_address" \
                    "$port" \
                    "$process" \
                    "Review whether this listening service should be bound to all network interfaces."
            fi
        fi
    done <<< "$PORTS"

    echo
}
