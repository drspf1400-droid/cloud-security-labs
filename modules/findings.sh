#!/bin/bash
FINDINGS=()
add_finding() {
    FINDINGS+=("$1")
}
show_findings(){
    echo
    echo "[+] Security Findings:"
    if [ ${#FINDINGS[@]} -eq 0 ]; then
        echo " NO findings detected"
        return
     fi
     for finding in "${FINDINGS[@]}"; do
        echo  "- $finding"
     done

}


