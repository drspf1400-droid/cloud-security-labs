#!/bin/bash
check_ssh(){
echo "[+] ssh service:"
if systemctl is-active --quiet ssh; then 
   echo -e "${GREEN}Running${NC}"
 else 
    echo -e "${YELLOW}Stopped or not install${NC}"
   fi 
if sudo sshd -T | grep -q "passwordauthentication yes"; then
  add_finding "MEDIIUM | SSH password Authentication Enable | Disable password login | / etc/ssh/sshd_config"
fi
}

