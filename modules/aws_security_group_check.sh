#!/bin/bash

check_aws_security_group() {
    echo "[+] AWS Security Group:"
    echo "Checking inbound rules..."

    AWS_SG_RULES_FILE="${AWS_SG_RULES_FILE:-/app/aws_security_group_rules.txt}"

if [ ! -f "$AWS_SG_RULES_FILE" ]; then
        echo "AWS Security Group data not found"
        return
    fi

    while IFS='|' read -r service port source; do

        case "$port" in
            22)
                if [ "$source" = "0.0.0.0/0" ]; then
                    echo "[HIGH] SSH (22) exposed to the internet"
                    add_finding "HIGH | SSH exposed to internet | Restrict port 22 | Allow only trusted IPs"
                else
                    echo "[OK] SSH (22) restricted"
                fi
                ;;

            3389)
                if [ "$source" = "0.0.0.0/0" ]; then
                    echo "[HIGH] RDP (3389) exposed to the internet"
                    add_finding "HIGH | RDP exposed to internet | Restrict port 3389 | Allow only trusted IPs"
                else
                    echo "[OK] RDP (3389) restricted"
                fi
                ;;

            80|443)
                echo "[INFO] $service ($port) publicly accessible"
                ;;

            *)
                echo "[INFO] $service ($port) → $source"
                ;;
        esac

    done < "$AWS_SG_RULES_FILE"
}
