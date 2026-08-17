#!/bin/bash
check_services(){
echo "[+] Running Services:"
services=("ssh" "nginx" "apache2" "mysql" "docker" "fail2ban")
for service in "${services[@]}"
do
    if systemctl is-active --quiet $service; then
  echo "$service : Running"
  else 
    echo "$service : Not Running"
    fi
 done
}
