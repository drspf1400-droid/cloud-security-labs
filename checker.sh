#!/bin/bash
source config/colors.sh
source modules/findings.sh
source modules/ssh_check.sh
source modules/firewall_check.sh
source modules/system_check.sh
source modules/resource_check.sh
source modules/ports_check.sh
source modules/updates_check.sh
source modules/services_check.sh
source modules/aws_security_group_check.sh
source modules/aws_iam_check.sh
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
    score=100

    # SSH password authentication
    if printf '%s\n' "${FINDINGS[@]}" | grep -q "SSH password authentication enabled"; then
        score=$((score - 20))
    fi

    # SSH root login
    if printf '%s\n' "${FINDINGS[@]}" | grep -q "SSH root login enabled"; then
        score=$((score - 20))
    fi

    # Firewall
    if printf '%s\n' "${FINDINGS[@]}" | grep -q "Firewall is inactive"; then
        score=$((score - 25))
    fi

    # Publicly exposed ports
    PUBLIC_PORTS=$(printf '%s\n' "${FINDINGS[@]}" | grep -c "Publicly exposed port detected" || true)
    if [ "$PUBLIC_PORTS" -gt 0 ]; then
        score=$((score - 15))
    fi
    # AWS IAM full access
    if printf '%s\n' "${FINDINGS[@]}" | grep -q "IAM policy has full access"; then
        score=$((score - 25))
    fi

    # AWS SSH exposed
    if printf '%s\n' "${FINDINGS[@]}" | grep -q "SSH exposed to internet"; then
        score=$((score - 20))
    fi

    # AWS RDP exposed
    if printf '%s\n' "${FINDINGS[@]}" | grep -q "RDP exposed to internet"; then
        score=$((score - 20))
    fi

    # Package updates
    if printf '%s\n' "${FINDINGS[@]}" | grep -q "Package updates available"; then
        score=$((score - 10))
    fi

    # Prevent negative scores
    if [ "$score" -lt 0 ]; then
        score=0
    fi

    echo "$score" > /tmp/security_score

    echo
    echo "[+] Security Score:"
    echo "${score}/100"
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

    for finding in "${FINDINGS[@]}"; do
        case "$finding" in

            *"Firewall is inactive"*)
                echo "[HIGH] Firewall is inactive"
                echo "Recommendation: Enable UFW firewall"
                echo "Command: sudo ufw enable"
                ;;

            *"SSH password authentication enabled"*)
                echo "[MEDIUM] SSH password authentication is enabled"
                echo "Recommendation: Disable password login"
                echo "Edit: /etc/ssh/sshd_config"
                ;;

            *"SSH root login enabled"*)
                echo "[HIGH] SSH root login is enabled"
                echo "Recommendation: Disable root login"
                echo "Edit: /etc/ssh/sshd_config"
                ;;

            *"Publicly exposed port detected"*)
                echo "[MEDIUM] Publicly exposed port detected"
                echo "Recommendation: Review exposed service and firewall rules"
                echo "Action: Restrict unnecessary public ports"
                ;;

            *"Package updates available"*)
                echo "[MEDIUM] Package updates are available"
                echo "Recommendation: Install available package updates"
                echo "Command: apt-get upgrade"
                ;;

            *"Update check unavailable"*)
                echo "[LOW] Update check unavailable"
                echo "Recommendation: Check package repositories and network connectivity"
                echo "Action: Run apt-get update manually"
                ;;

            *"SSH configuration could not be evaluated"*)
                echo "[HIGH] SSH configuration could not be evaluated"
                echo "Recommendation: Check SSH server configuration"
                echo "Command: sshd -t"
                ;;

*"SSH exposed to internet"*)
    echo "[HIGH] SSH is exposed to the internet"
    echo "Recommendation: Restrict SSH access to trusted IP addresses"
    echo "Action: Limit port 22 in the AWS Security Group"
    ;;

*"RDP exposed to internet"*)
    echo "[HIGH] RDP is exposed to the internet"
    echo "Recommendation: Restrict RDP access to trusted IP addresses"
    echo "Action: Limit port 3389 in the AWS Security Group"
    ;;

*"IAM policy has full access"*)
    echo "[HIGH] IAM policy has full access"
    echo "Recommendation: Apply the principle of least privilege"
    echo "Action: Restrict IAM actions and resources"
    ;;
        esac
    done

    echo
}

generate_html_report(){
    SCORE=$(cat /tmp/security_score)
    RISK=$RISK_LEVEL

    mkdir -p report

    cat <<EOF > report/security_report.html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Linux Security Checker Pro Report</title>

<style>
body {
    font-family: Arial, sans-serif;
    margin: 40px;
    background: #f4f6f8;
    color: #222;
}

.container {
    max-width: 1000px;
    margin: auto;
    background: white;
    padding: 35px;
    border-radius: 12px;
}

h1 {
    margin-bottom: 5px;
}

h2 {
    margin-top: 30px;
    border-bottom: 1px solid #ddd;
    padding-bottom: 8px;
}

.score {
    font-size: 42px;
    font-weight: bold;
}

.risk {
    font-size: 24px;
    font-weight: bold;
}

.finding,
.recommendation {
    padding: 12px;
    margin: 8px 0;
    background: #f7f7f7;
    border-radius: 6px;
}

.meta {
    color: #555;
}
</style>
</head>

<body>
<div class="container">

<h1>Linux Security Checker Pro</h1>
<p class="meta">Automated Linux Security Audit Report</p>

<h2>System Information</h2>
<p>Hostname: $(hostname)</p>
<p>Kernel: $(uname -r)</p>
<p>OS: $(grep PRETTY_NAME /etc/os-release | cut -d '"' -f2)</p>
<p>Audit Time: $(date)</p>

<h2>Security Score</h2>
<div class="score">${SCORE}/100</div>

<h2>Risk Level</h2>
<div class="risk">${RISK}</div>

<h2>Audit Status</h2>
<p>Security checks completed successfully.</p>

<h2>Security Findings</h2>
EOF

    for finding in "${FINDINGS[@]}"; do
        echo "<div class=\"finding\">$finding</div>" >> report/security_report.html
    done

    cat <<EOF >> report/security_report.html

<h2>Security Recommendations</h2>
EOF

    for finding in "${FINDINGS[@]}"; do
        case "$finding" in

            *"Firewall is inactive"*)
                echo '<div class="recommendation"><b>Firewall:</b> Enable UFW firewall.<br>Command: sudo ufw enable</div>' >> report/security_report.html
                ;;

            *"SSH password authentication enabled"*)
                echo '<div class="recommendation"><b>SSH Password Authentication:</b> Disable password login in /etc/ssh/sshd_config.</div>' >> report/security_report.html
                ;;

            *"SSH root login enabled"*)
                echo '<div class="recommendation"><b>SSH Root Login:</b> Disable root login in /etc/ssh/sshd_config.</div>' >> report/security_report.html
                ;;

            *"Publicly exposed port detected"*)
                echo '<div class="recommendation"><b>Public Port:</b> Review exposed services and restrict unnecessary public ports.</div>' >> report/security_report.html
                ;;

            *"Package updates available"*)
                echo '<div class="recommendation"><b>Updates:</b> Install available package updates.</div>' >> report/security_report.html
                ;;

            *"Update check unavailable"*)
                echo '<div class="recommendation"><b>Update Check:</b> Verify package repository and network connectivity.</div>' >> report/security_report.html
                ;;
*"SSH exposed to internet"*)
    echo '<div class="recommendation"><b>AWS SSH:</b> Restrict port 22 to trusted IP addresses in the Security Group.</div>' >> report/security_report.html
    ;;

*"RDP exposed to internet"*)
    echo '<div class="recommendation"><b>AWS RDP:</b> Restrict port 3389 to trusted IP addresses in the Security Group.</div>' >> report/security_report.html
    ;;

*"IAM policy has full access"*)
    echo '<div class="recommendation"><b>AWS IAM:</b> Apply least privilege and restrict IAM actions and resources.</div>' >> report/security_report.html
    ;;
        esac
    done

    cat <<EOF >> report/security_report.html

<h2>Audit Summary</h2>
<p>Linux Security Checker Pro completed an automated security assessment of the target system.</p>

</div>
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
check_updates
check_aws_security_group
check_aws_iamcheck_aws_security_group
check_aws_iam
calculate_score
calculate_risk_level
show_findings
show_recommendations
generate_html_report

echo
echo "Finished"






