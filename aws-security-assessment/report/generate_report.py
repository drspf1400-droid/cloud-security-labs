#!/usr/bin/env python3

import json
from datetime import datetime


FINDINGS_FILE = "aws-security-assessment/iam/iam-findings.json"
OUTPUT_FILE = "aws-security-assessment/report/aws_security_report.html"


def main():
    with open(FINDINGS_FILE, "r") as file:
        findings = json.load(file)

    score = 100

    penalties = {
        "CRITICAL": 40,
        "HIGH": 30,
        "MEDIUM": 15,
        "LOW": 5
    }

    for finding in findings:
        score -= penalties.get(finding.get("severity", "LOW"), 0)

    score = max(score, 0)

    severities = [f.get("severity", "LOW") for f in findings]

    if "CRITICAL" in severities:
        risk = "CRITICAL"
    elif "HIGH" in severities:
        risk = "HIGH"
    elif "MEDIUM" in severities:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    finding_rows = ""

    for finding in findings:
        finding_rows += f"""
        <tr>
            <td>{finding['id']}</td>
            <td>{finding['title']}</td>
            <td>{finding['severity']}</td>
            <td>{finding['category']}</td>
            <td>{finding['recommendation']}</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>AWS Security Assessment</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
        }}

        h1 {{
            margin-bottom: 5px;
        }}

        .summary {{
            margin: 30px 0;
        }}

        .score {{
            font-size: 42px;
            font-weight: bold;
        }}

        .risk {{
            font-size: 24px;
            font-weight: bold;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}

        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}

        th {{
            background: #f2f2f2;
        }}

        footer {{
            margin-top: 40px;
            font-size: 12px;
        }}
    </style>
</head>

<body>

<h1>AWS Cloud Security Assessment</h1>

<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

<div class="summary">

    <h2>Security Score</h2>
    <div class="score">{score}/100</div>

    <h2>Risk Level</h2>
    <div class="risk">{risk}</div>

</div>

<h2>Findings</h2>

<table>

<tr>
    <th>ID</th>
    <th>Title</th>
    <th>Severity</th>
    <th>Category</th>
    <th>Recommendation</th>
</tr>

{finding_rows}

</table>

<footer>
    AWS Cloud Security Assessment — Portfolio Lab
</footer>

</body>
</html>
"""

    with open(OUTPUT_FILE, "w") as file:
        file.write(html)

    print("[+] AWS Security Report generated")
    print(f"[+] Score: {score}/100")
    print(f"[+] Risk: {risk}")
    print(f"[+] Report: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
