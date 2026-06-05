# ☁️ Cloud Security Posture Scanner

**Author:** Ayush Solanki  
**Tech Stack:** AWS Lambda, S3, EC2, IAM, EventBridge, Python 3.12, boto3

[![AWS](https://img.shields.io/badge/AWS-Lambda%20%7C%20S3%20%7C%20EC2-orange)](https://aws.amazon.com)
[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://python.org)
[![Security](https://img.shields.io/badge/Security-CSPM-red)](https://owasp.org)

---

## 📌 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Priority Scoring Formula](#priority-scoring-formula)
- [What It Scans](#what-it-scans)
- [Deployment Guide](#deployment-guide)
- [Code Explanation](#code-explanation)
- [Example Output](#example-output)
- [Testing Auto-Remediation](#testing-auto-remediation)
- [Interview Q&A](#interview-qa)
- [Future Improvements](#future-improvements)

---

## 📖 Overview

This serverless **Cloud Security Posture Management (CSPM)** tool automatically scans your AWS environment for common misconfigurations that could lead to data leaks or compliance violations.

It **prioritizes findings** using a cost‑aware formula, **auto‑remediates** cheap, safe issues (public S3 buckets), and **reports** others (unencrypted EBS volumes) for manual review.

The scanner runs on AWS Lambda and can be scheduled (e.g., daily) to ensure continuous compliance.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **S3 Public Bucket Detection** | Checks ACLs and bucket policies for public access |
| 🛡️ **Auto-Remediation** | Blocks all public access to vulnerable buckets automatically |
| 💾 **EBS Encryption Check** | Identifies unencrypted volumes (reports only) |
| 📊 **Priority Scoring** | Ranks findings by risk, cost impact, and fix cost |
| ⏱️ **Serverless** | Runs on Lambda – pay only when used |
| 📅 **Scheduled Scans** | EventBridge trigger for daily or custom schedules |

---

## 🏗️ Architecture
┌─────────────────┐
│ EventBridge │
│ (daily cron) │
└────────┬────────┘
│ triggers
▼
┌─────────────────┐
│ AWS Lambda │
│ (Python 3.12) │
└────────┬────────┘
│
┌────┴────┬──────────────┐
▼ ▼ ▼
┌───────┐ ┌───────┐ ┌──────────┐
│ S3 │ │ EC2 │ │ CloudWatch│
│ Scan │ │ Scan │ │ Logs │
└───┬───┘ └───┬───┘ └─────┬────┘
│ │ │
▼ ▼ ▼
┌────────────────────────────────┐
│ Priority Scoring & Output │
│ (JSON + CloudWatch logs) │
└────────────────────────────────┘


---

## 🧮 Priority Scoring Formula

Each finding receives a **priority score** – higher means fix first.

| Parameter | Description | Example Values |
|-----------|-------------|----------------|
| `risk_score` | Severity (1-10) | Public bucket = 9, Unencrypted volume = 7 |
| `cost_impact` | Estimated monthly cost if exploited (USD) | $1000 (data leak), $500 (compliance fine) |
| `fix_cost` | One‑time cost to remediate (USD) | $0 (ACL change), $0.10 (encrypt volume) |

### Example Calculation

**Public bucket:** `(9 × 0.5) + (1000 × 0.3) − (0 × 0.2) = 4.5 + 300 − 0 = 304.5`  
**Unencrypted volume:** `(7 × 0.5) + (500 × 0.3) − (0.1 × 0.2) = 3.5 + 150 − 0.02 = 153.48`

Public bucket → higher priority → fixed first.

---

## 🔍 What It Scans

### 1. S3 Buckets (Public Access)
- **Check:** Bucket ACLs (`get_bucket_acl`) and bucket policy status (`get_bucket_policy_status`)
- **Risk if ignored:** Data leak, reputational damage, regulatory fines
- **Action:** Auto-remediate by enabling **Block Public Access** (all four settings)

### 2. EBS Volumes (Encryption)
- **Check:** `Encrypted` flag from `describe_volumes()`
- **Risk if ignored:** Compliance violations (HIPAA, GDPR, PCI‑DSS)
- **Action:** Report only – encryption requires snapshot + copy + replace (risky/downtime)

---

## 🚀 Deployment Guide

### Prerequisites
- AWS account (Free Tier works)
- IAM permissions to create Lambda, roles, and policies

### Step‑by‑Step

#### 1. Create Lambda Function
- Go to AWS Lambda → **Create function**
- Name: `SecurityPostureScanner`
- Runtime: Python 3.12
- Architecture: x86_64
- Permissions: Create a new basic role (we'll attach policies later)

#### 2. Set Timeout
- Configuration → General configuration → Edit
- Timeout: **1 minute** (scanning many resources needs time)

#### 3. Attach IAM Policies
- Go to **Configuration → Permissions** → Click role name
- **Add permissions → Attach policies**
- Search and attach:
  - `AmazonS3ReadOnlyAccess`
  - `AmazonS3FullAccess` (for auto‑remediation)
  - `AmazonEC2ReadOnlyAccess`

#### 4. Paste Code
- Copy `lambda_function.py` content into the code editor
- Click **Deploy**

#### 5. Test
- Create a test event (any JSON, e.g., `{}`)
- Click **Test** – you should see findings (if any misconfigurations exist)

#### 6. (Optional) Schedule Daily Scan
- **Add trigger** → EventBridge
- Rule name: `DailySecurityScan`
- Schedule expression: `cron(0 0 * * ? *)` (midnight UTC)
- Click **Add**

---

## 📝 Code Explanation (Key Sections)

| Code Block | What It Does |
|------------|---------------|
| `s3.list_buckets()` | Gets all S3 buckets in the account |
| `s3.get_bucket_acl()` | Reads ACL to see if `AllUsers` or `AuthenticatedUsers` have access |
| `s3.get_bucket_policy_status()` | Checks if bucket policy grants public access |
| `s3.put_public_access_block()` | **Auto-remediation** – blocks all public access |
| `ec2.describe_volumes()` | Lists all EBS volumes |
| `vol.get('Encrypted')` | Checks encryption status |
| Priority scoring loop | Calculates `priority_score` for each finding |
| `findings.sort(reverse=True)` | Orders findings from highest to lowest priority |

---

## 📊 Example Output (Real Test)

### Response JSON
```json
{
  "scan_time": "2026-06-05T02:32:00.023773",
  "findings": [
    {
      "type": "public_bucket",
      "resource": "test-public-bucket-ayush",
      "risk_score": 9,
      "cost_impact": 1000.0,
      "fix_cost": 0.0,
      "details": "Bucket test-public-bucket-ayush is publicly accessible",
      "priority_score": 304.5
    },
    {
      "type": "unencrypted_volume",
      "resource": "vol-01339983fc3a2bfca",
      "risk_score": 7,
      "cost_impact": 500.0,
      "fix_cost": 0.1,
      "priority_score": 153.48
    }
  ],
  "remediations": [
    "Blocked public access on test-public-bucket-ayush"
  ]
}


## CloudWatch Logs
Scan completed at 2026-06-05T02:32:00.023773
Total findings: 2
 - public_bucket: test-public-bucket-ayush (priority 304.5)
 - unencrypted_volume: vol-01339983fc3a2bfca (priority 153.48)
Auto-remediations applied: 1
   ✓ Blocked public access on test-public-bucket-ayush



Ayush Solanki  |  ayush.solanki.itims@gmail.com