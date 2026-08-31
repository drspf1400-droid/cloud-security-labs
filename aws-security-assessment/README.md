# AWS Cloud Security Assessment

A practical AWS security assessment toolkit designed to identify common cloud security misconfigurations.

## Current Coverage

### IAM
- Excessive IAM permissions
- Wildcard permissions
- Least privilege analysis

### S3
- Public bucket policy detection
- Public object access detection

## Assessment Pipeline

Policy
  ↓
Security Analyzer
  ↓
Findings
  ↓
JSON Output
  ↓
Security Score
  ↓
Risk Level
  ↓
HTML Security Report

## Current Findings

| ID | Finding | Severity |
|----|---------|----------|
| IAM-001 | Excessive IAM Permissions | HIGH |
| S3-001 | Public S3 Bucket | CRITICAL |

## Example Assessment

Security Score: 30/100

Risk Level: CRITICAL

Total Findings: 2

## Project Structure

aws-security-assessment/
├── iam/
├── s3/
├── report/
└── security_assessment.py

## Technologies

- Python
- Bash
- JSON
- AWS IAM
- AWS S3
- HTML

## Purpose

This project demonstrates practical cloud security assessment,
misconfiguration detection, risk classification, and security reporting.

## Disclaimer

This project is intended for authorized security testing,
educational labs, and portfolio demonstration.
