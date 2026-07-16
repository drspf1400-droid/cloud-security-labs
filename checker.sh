#!/bin/bash
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
BLUE="\e[34m"
NC="\e[0m"
show_header()
{
echo -e "${BLUE}"
echo "=========="
echo "Linux Security Checker Pro v1.0"
echo "=========="
echo -e"${NC}"
}
check_system()
{
echo
echo "[+] Hoatname:"
hostname

echo
echo "[+] Current User:"
whoami

echo
echo "[+] Kernel Version:"
uname -r
}
echo
echo "[+] Uptime:"
uptime
check_resources()
{
echo
echo "[+] Cpu Usage :"
top -bn1 | grep "%cpu"
echo
echo "[+] RAM Usage:"
free -h
echo
echo "[+] Disk Usage:"
df -h /
echo
}
echo "[+] Internet:"
ping -c 1 8.8.8.8 >/dev/null && echo -e "${GREEN}Connected${NC}" || echo -e "${RED}Disconnected${NC}"
echo
check_ssh(){
if systemctl is-active --quiet ssh; then
   echo -e "${GREEN}SSH: Running${NC}"
else
   echo "${RED}SSH : Stopped${NC}"
fi
}
echo
echo "[+] Firewall:"
#ufw status
show_header
check_system
check_resources
check_ssh
echo
echo "Finished"


 


