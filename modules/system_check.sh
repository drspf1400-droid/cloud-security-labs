#!/bin/bash
check_system(){
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
echo "[+] Uptime:"
uptime -p
}
