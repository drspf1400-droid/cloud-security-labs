#!/bin/bash

GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
BLUE="\e[34m"
NC="\e[0m"

show_header() {
    echo -e "${BLUE}==================================${NC}"
    echo " Linux Security Checker Pro v1.1"
    echo -e "${BLUE}==================================${NC}"
}

check_system() {
    echo
    echo "[+] Hostname:"
    hostname

    echo
    echo "[+] Current User:"
    whoami

    echo
    echo "[+] Kernel Version:"
    uname -r

    echo
    echo "[+] Uptime:"
    uptime -p
}

check_resources() {
    echo
    echo "[+] CPU Usage:"
    top -bn1 | grep -i "Cpu(s)" | head -n 1

    echo
    echo "[+] RAM Usage:"
    free -h

    echo
    echo "[+] Disk Usage:"
    df -h /
}

check_internet() {
    echo
    echo "[+] Internet:"

    if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
        echo -e "${GREEN}Connected${NC}"
    else
        echo -e "${RED}Disconnected${NC}"
    fi
}

check_ssh() {
    echo
    echo "[+] SSH Service:"

    if systemctl is-active --quiet ssh; then
        echo -e "${GREEN}Running${NC}"
    else
        echo -e "${YELLOW}Stopped or not installed${NC}"
    fi
}

check_firewall() {
calculate_score
    echo
    echo "[+] Firewall:"

    if systemctl is-active --quiet ufw; then
        echo -e "${GREEN}UFW is active${NC}"
    else
        echo -e "${RED}UFW is inactive or not installed${NC}"
    fi
}
calculate_score() {
    score=0

    systemctl is-active --quiet ufw && score=$((score + 40))

    grep -REiq '^[[:space:]]*PermitRootLogin[[:space:]]+(no|prohibit-password)' \
    /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null \
    && score=$((score + 30))

    grep -REiq '^[[:space:]]*PasswordAuthentication[[:space:]]+no' \
    /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null \
    && score=$((score + 30))

    echo
    echo "[+] Security Score:"
    echo "${score}/100"
}
show_header
check_system
check_resources
check_internet
check_ssh
check_firewall

echo
echo -e "${BLUE}Finished${NC}"


 


