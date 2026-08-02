#!/bin/bash
check_ssh(){
echo "[+] ssh service:"
if systemctl is-active --quiet ssh; then 
   echo -e "${GREEN}Running${NC}"
 else 
    echo -e "${YELLOW}Stopped or not install${nc}"
   fi 
}

