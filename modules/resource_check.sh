#!/bin/bash
check_resources(){
echo
echo "[+] CPU Usage:"
top -bn1 | grep "Cpu(s)"
echo
echo "[+] RAM Usage:"
free -h
echo
echo "[+] Disk Usage:"
df -h /
}
