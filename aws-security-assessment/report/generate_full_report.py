#!/usr/bin/env python3

import json
from datetime import datetime


FINDINGS_FILES = [
    "aws-security-assessment/iam/iam-findings.json",
    "aws-security-assessment/s3/s3-findings.json"
]

OUTPUT_FILE = "aws-security-assessment/report/aws_full_security_report.html"

PENALTIES = {
    "CRITICAL": 40,
    "HIGH": 30,
    "MEDIUM": 15,
    "LOW": 5
}


def load_findings():
    findings = []

    for filename in FINDINGS_FILES:
        with open(filename, "r") as file:
            findings.extend(json.load(file))

    return findings


def calculate_score(findings):
    score = 100

    for finding in findings:
        score -= PENALTIES.get(
            finding.get("severity", "LOW"),
            0
        )

    return max(score, 0)


def calculate_risk(findings):
    severities = [f.get("severity", "LOW") for f in findings]

    if "CRITICAL" in severities:
        return "CRITICAL"
    if "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities:
        return "MEDIUM"

    return "LOW"


def main():

    findings = load_findings()

    score = calculate_score(findings)
    risk = calculate_risk(findings)

    rows = ""

    for finding in findings:
        rows += f"""
        <tr>
            <td>{finding['id']}</td>
            <td>{finding['title']}</td>
            <td>{finding['severity']}</td>
            <td>{finding['category']}</td>
            <td>{finding['risk']}</td>
            <td>{finding['recommendation']}</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>AWS Cloud Security Assessment</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    background: #f7f7f7;
}}

.container {{
    max-width: 1200px;
    margin: auto;
    background: white;
    padding: 40px;
}}

h1 {{
    margin-bottom: 5px;
}}

.summary {{
    display: flex;
    gap: 60px;
    margin: 30px 0;
}}

.metric {{
    font-size: 36px;
    font-weight: bold;
}}

.label {{
    color: #666;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 30px;
}}

th, td {{
    border: 1px solid #ddd;
    padding: 12px;
    text-align: left;
}}

th {{
    background: #eee;
}}

footer {{
    margin-top: 40px;
    color: #777;
    font-size: 12px;
}}

</style>

</head>

<body>

<div class="container">

<h1>AWS Cloud Security Assessment</h1>

<p>
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
</p>

<div class="summary">

<div>
<div class="label">Security Score</div>
<div class="metric">{score}/100</div>
</div>

<div>
<div class="label">Risk Level</div>
<div class="metric">{risk}</div>
</div>

<div>
<div class="label">Total Findings</div>
<div class="metric">{len(findings)}</div>
</div>

</div>

<h2>Security Findings</h2>

<table>

<tr>
<th>ID</th>
<th>Finding</th>
<th>Severity</th>
<th>Category</th>
<th>Risk</th>
<th>Recommendation</th>
</tr>

{rows}

</table>

<footer>

AWS Cloud Security Assessment — Portfolio Lab

</footer>

</div>

</body>

</html>
"""

    with open(OUTPUT_FILE, "w") as file:
        file.write(html)

    print("[+] Full AWS Security Report generated")
    print(f"[+] Findings: {len(findings)}")
    print(f"[+] Score: {score}/100")
    print(f"[+] Risk: {risk}")
    print(f"[+] Report: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
