#!/bin/bash
echo "----"
echo "Linux Security Audit"
echo "----"
echo
echo "[1] Hostname"
echo

echo "[2] Current User"
whoami
echo

echo "[3] Kernel Version"
uname -r
echo
 
echo "[4] OS Information"
cat /etc/os-release
echo

echo "[5] Firewall"
if systemctl is-active --quiet ufw ;
then
   echo "UFW : ACTIVE" 
 else
   echo "UFW : INACTIVE"
 fi
 
    echo "[6] SSH Service"
if systemctl is-active --quiet ssh;

then 
   echo "ssh : RUNNING"

 else
    echo "SSH : STOPPED"
 
 fi 
echo
echo "Audit Finished"

