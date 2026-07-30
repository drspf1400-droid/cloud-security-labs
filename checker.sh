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
echo "[+] Operating System:"
grep PRETTY_NAME /etc/os-release | cut -d '"' -f2
echo

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

    sudo sshd -T | grep -Eq "permitrootlogin (no|without-password)" && score=$((score + 30))
    sudo sshd -T | grep -q "passwordauthentication no" && score=$((score + 30))

    

    echo
    echo "[+] Security Score:"
    echo  "${score}/100"

show_recommendations() {
echo
echo "[+] Security Recommendations:"
if ! systemctl is-active --quiet ufw; then
echo "[HIGH] Firewall is inactive"
echo "Recommendation: Enable UFW firewall"
echo "Command: sudo ufw enable"
fi
if ! sudo sshd -T | grep -q "passwordauthentication no"; then
echo "[MEDIUM] SSH password Authentication is enabled"
echo "Recommendation: Disable password login"
echo "Edit: /etc/ssh/sshd_config"
fi
if ! sudo sshd -T | grep -Eq "permitrootlogin (no|without-password)"; then
echo "[HIGH] Root SSH Login is allowed"
echo "Recommendation: Disable root login"
echo "Edit: /etc/ssh/sshd_config"
fi
}
}
show_header
check_system
check_resources
check_internet
check_ssh
check_firewall
show_recommendations
echo
echo -e "${BLUE}Finished${NC}"


 


