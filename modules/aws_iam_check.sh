#!/bin/bash

check_aws_iam() {
    echo "[+] AWS IAM:"
    echo "Checking IAM policies..."

    if [ ! -f /app/aws_iam_policies.txt ]; then
        echo "AWS IAM data not found"
        return
    fi

    while IFS='|' read -r policy action resource; do

        if [ "$action" = "*" ] && [ "$resource" = "*" ]; then
            echo "[HIGH] $policy has full access"
            add_finding "HIGH | IAM policy has full access | Apply least privilege | Restrict actions and resources"
        elif [ "$action" = "*" ]; then
            echo "[MEDIUM] $policy allows all actions"
            add_finding "MEDIUM | IAM policy allows all actions | Restrict IAM actions | Allow only required actions"
        elif [ "$resource" = "*" ]; then
            echo "[MEDIUM] $policy allows access to all resources"
            add_finding "MEDIUM | IAM policy allows all resources | Restrict IAM resources | Limit resource scope"
        else
            echo "[OK] $policy follows restricted access"
        fi

    done < /app/aws_iam_policies.txt
}
