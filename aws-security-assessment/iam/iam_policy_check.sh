#!/bin/bash

POLICY_FILE="$1"

if [ -z "$POLICY_FILE" ]; then
    echo "Usage: $0 <policy.json>"
    exit 1
fi

if [ ! -f "$POLICY_FILE" ]; then
    echo "[ERROR] Policy file not found: $POLICY_FILE"
    exit 1
fi

echo "[+] AWS IAM Policy Security Check"
echo "[+] Policy: $POLICY_FILE"
echo

if grep -q '"Action": "\*"' "$POLICY_FILE" && \
   grep -q '"Resource": "\*"' "$POLICY_FILE"; then

    echo "[HIGH] Excessive IAM permissions detected"
    echo "       Action: *"
    echo "       Resource: *"
    echo "       Recommendation: Apply least privilege."
    exit 1
fi

echo "[PASS] No full wildcard permissions detected."
exit 0
