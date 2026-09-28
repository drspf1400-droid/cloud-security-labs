#!/bin/bash

check_firewall() {
    echo "[+] Firewall:"

    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        echo -e "${GREEN}UFW is active${NC}"
    else
        echo -e "${RED}UFW is inactive or not installed${NC}"

        add_finding "HIGH | Firewall is inactive | Enable UFW firewall | sudo ufw enable"

        add_structured_finding \
            "FW-001" \
            "firewall" \
            "Host firewall is inactive" \
            "HIGH" \
            "linux_configuration" \
            "firewall_check" \
            "command_output" \
            "ufw status" \
            "status" \
            "inactive" \
            "Enable and configure the host firewall according to the required network policy."
    fi
}
