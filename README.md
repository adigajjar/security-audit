# 🛡️ Lucifer Security Audit Module

## Overview

The `security-audit` module is the core vulnerability assessment and penetration testing (VAPT) engine of the Lucifer framework. It provides automated security scanning for cloud environments, evaluating infrastructure against a set of predefined security rules and proactively verifying vulnerabilities using integrated chaos engineering experiments.

Unlike traditional static scanners, Lucifer's Security Audit module doesn't just report a "potential" vulnerability—it can execute real-world attack simulations to verify the actual impact and detectability of identified security gaps.

## 🚀 Key Features

- **Automated Cloud Scanning**: Deep inspection of AWS services to collect security-relevant metadata.
- **Rule-Based Evaluation**: Flexible and extensible YAML-based security rules covering IAM, S3, EC2, RDS, and Lambda.
- **VAPT-Driven Chaos**: Automatically triggers targeted chaos engineering experiments when a vulnerability is found to verify its impact.
- **Detailed Reporting**: Generates comprehensive VAPT reports in Markdown format, including executive summaries, detailed findings, and remediation steps.
- **Seamless Integration**: Designed to work as a standalone tool or as part of a larger DevSecOps pipeline.

## 🛠️ Supported Services (AWS)

| Service | Audit Scope |
| :--- | :--- |
| **IAM** | Root MFA, Wildcard Policies, Credential Rotation, Role Trust Policies. |
| **S3** | Public Access, Versioning, Encryption, MFA-Delete, Access Logging. |
| **EC2** | Open Ports (SSH/RDP), Metadata Service (IMDSv1), Attachment state. |
| **RDS** | Public Accessibility, Multi-AZ Resilience, Encryption at Rest. |
| **Lambda** | Function URL Authentication, Dead Letter Queues (DLQ), VPC Config. |
| **Beanstalk** | Environment Health, Platform Updates, Instance Config. |

## 🏗️ How it Works

1. **Connector**: Establishes a secure connection to the target cloud account using cross-account roles and external IDs.
2. **Scanner**: Performs parallel scanning of requested services to build a snapshot of the environment's state.
3. **Rules Engine**: Loads YAML-defined rules and evaluates the scanned data against them.
4. **Chaos Trigger**: If a rule fails and has a linked experiment, the module triggers a "Verification Attack" (e.g., simulating credential theft or data exfiltration).
5. **Reporting**: Aggregates finding data and experiment logs into a structured `vapt_report.md`.

## 🚥 Getting Started

### Prerequisites

- [Go](https://golang.org/doc/install) (1.21 or higher)
- AWS Credentials configured with sufficient permissions to scan resources.
- A Cross-Account Role named `VAPTAuditRole` in the target account (if using cross-account mode).

### Usage

Run the auditor against all supported services:

```bash
go run main.go aws all
```

Run against specific services:

```bash
go run main.go aws iam s3 ec2
```

### Output

The module generates two primary outputs:
1. **JSON Output**: Printed to stdout for programmatic consumption.
2. **`vapt_report.md`**: A human-readable report with detailed findings and remediation guides.

## 📝 Rule Definition

Rules are defined in YAML files located in `rules/aws/`. Each rule follows this structure:

```yaml
rules:
  - id: A-IAM-1
    name: "Overly Permissive Wildcard Policy"
    severity: CRITICAL
    description: "IAM policy allows wildcard actions (*) on wildcard resources (*)."
    remediation: "Replace wildcard actions with least-privilege specific permissions."
    type: iam_policy_analysis
    check:
      operator: "contains"
      value: "*"
    benchmarks:
      cis_control: "1.16"
      nist_csf: "PR.AC-4"
      mitre_technique: "T1098"
    chaos_trigger:
      experiment: "simulate_privilege_escalation"
      target_type: "iam_user"
      impact: "privilege_escalation"
```

## 📁 Directory Structure

- `/connector`: Cloud provider connection logic.
- `/scanner`: Service-specific metadata collection logic.
- `/rules`: Rule models, evaluator, and YAML definitions.
- `/report`: Markdown report generation templates and logic.
- `/main.go`: Entry point for the audit CLI.

---

*Part of the [Lucifer](https://github.com/ShubhankarSalunke/Lucifer) Security Framework.*
