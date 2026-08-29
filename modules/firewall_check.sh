#!/bin/bash

check_firewall() {
    echo "[+] Firewall:"

    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        echo -e "${GREEN}UFW is active${NC}"
    else
        echo -e "${RED}UFW is inactive or not installed${NC}"
        add_finding "HIGH | Firewall is inactive | Enable UFW firewall | sudo ufw enable"
    fi
}
