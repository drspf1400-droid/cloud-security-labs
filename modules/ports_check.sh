#!/bin/bash
check_ports(){
  echo "[+] Listening Ports:"
  sudo ss -lntupH
  echo
  while read -r proto state recvq local pee process; do
     port="${local##*:}"
     if [[ "$local" == 0.0.0.0:* || "$local" == \[::\]:* ]]; then
        if [[ "$port" != "22" ]]; then
            add_finding "MEDIUM | Publicly exposed port detected | $local  |Review firewall/service configuratuion"
         fi

      fi
    done <  <(sudo ss -lntupH)
}
