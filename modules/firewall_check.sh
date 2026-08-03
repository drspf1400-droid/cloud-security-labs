#!/bin/bash
check_firewall(){
echo "[+] Firewall:"
if systemctl is-active --quiet ufw; then
    echo -e "{GREEN}UFW is active${NC}"
 else
    echo -e "${RED}UFW is inactive or not installed${NC}"
fi
}
