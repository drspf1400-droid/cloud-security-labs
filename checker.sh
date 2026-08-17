#!/bin/bash
source config/colors.sh
source modules/findings.sh
source modules/ssh_check.sh
source modules/firewall_check.sh
source modules/system_check.sh
source modules/resource_check.sh
source modules/ports_check.sh
source modules/services_check.sh
type show_findings
show_header() {
    echo -e "${BLUE}==================================${NC}"
    echo " Linux Security Checker Pro v1.1"
    echo -e "${BLUE}==================================${NC}"
}


check_internet() {
    echo
    echo "[+] Internet:"

    if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
        echo -e "${GREEN}Connected${NC}"
    else
        echo -e "${RED}Disconnected${NC}"
    fi
}




calculate_score() {
    score=0

    systemctl is-active --quiet ufw && score=$((score + 40))

    sudo sshd -T | grep -Eq "permitrootlogin (no|without-password)" && score=$((score + 30))
    sudo sshd -T | grep -q "passwordauthentication no" && score=$((score + 30))

    
echo "$score" > /tmp/security_score
    echo
    echo "[+] Security Score:"
    echo  "${score}/100"
}
calculate_risk_level(){
if [ "$score" -ge 80 ]; then
RISK_LEVEL="LOW"
elif [ "$score" -ge 50 ]; then
RISK_LEVEL="MEDIUM"
else
RISK_LEVEL="HIGH"
fi
echo
echo "[+] Risk Level:"
echo "$RISK_LEVEL"
}
show_recommendations() {
echo
echo "[+] Security Recommendations:"
if ! systemctl is-active --quiet ufw; then
echo "[HIGH] Firewall is inactive"
echo "Recommendation: Enable UFW firewall"
echo "Command: sudo ufw enable"
fi
if ! sudo sshd -T | grep -q "passwordauthentication no"; then
echo "[MEDIUM] SSH password Authentication is enabled"
echo "Recommendation: Disable password login"
echo "Edit: /etc/ssh/sshd_config"
fi
if ! sudo sshd -T | grep -Eq "permitrootlogin (no|without-password)"; then
echo "[HIGH] Root SSH Login is allowed"
echo "Recommendation: Disable root login"
echo "Edit: /etc/ssh/sshd_config"
fi
}


generate_html_report(){

SCORE=$(cat /tmp/security_score)
RISK=$RISK_LEVEL

mkdir -p report

cat <<EOF > report/security_report.html
<html>
<body>

<h1>Linux Security Checker Pro Report</h1>

<h2>System</h2>
<p>Hostname: $(hostname)</p>
<p>Kernel: $(uname -r)</p>
<p>OS: $(grep PRETTY_NAME /etc/os-release | cut -d '"' -f2)</p>

<h2>Security Score</h2>
<p>Score: ${SCORE}/100</p>

<h2>Risk Level</h2>
<p>${RISK}</p>

<h2>Status</h2>
<p>Security checks completed successfully.</p>

<h2>Security Findings</h2>

EOF


if [ ${#FINDINGS[@]} -eq 0 ]; then

echo "<p>No findings detected</p>" >> report/security_report.html

else

for finding in "${FINDINGS[@]}"; do
echo "<p>- $finding</p>" >> report/security_report.html
done

fi


cat <<EOF >> report/security_report.html

</body>
</html>
EOF


echo "[+] HTML Report Created"

}
show_header
check_system
check_resources
check_internet
check_ssh
check_firewall
check_ports
check_services
calculate_score
calculate_risk_level
show_findings
show_recommendations
generate_html_report

echo
echo -e "${BLUE}Finished${NC}"


 



