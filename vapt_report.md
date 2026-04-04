# Vulnerability Assessment & Penetration Testing (VAPT) Report
**Date:** Thu, 02 Apr 2026 20:06:57 IST

## Executive Summary
This report summarizes the results of an automated security audit and subsequent chaos engineering experiments. It details identified vulnerabilities, misconfigurations, and validated exploits alongside detailed experiment tracking.

### Summary Statistics
- **Total Rules Evaluated:** 20
- **Passed:** 11
- **Failed:** 9
- **Error:** 0

## Detailed Findings with Verified Exploit Testing

### 3. Missing MFA on Privileged IAM User (Rule ID: A-IAM-3)
- **Severity:** HIGH
- **Status:** FAIL
- **Description:** IAM user with admin permissions directly attached does not have MFA enabled exposing privileged access to credential theft.
- **Remediation:** Enforce MFA for all IAM users with admin or elevated permissions using an IAM policy condition.

---

### 5. Cross-Account Role Trust Misconfiguration (Rule ID: A-IAM-5)
- **Severity:** HIGH
- **Status:** FAIL
- **Description:** IAM role has an overly permissive trust policy allowing any principal (*) to assume it enabling unauthorized cross-account access.
- **Remediation:** Restrict role trust policies to specific trusted account IDs and require external ID conditions.

---

### 9. Unauthenticated Lambda URL Invocation Exposure (Rule ID: A-LAM-3)
- **Severity:** CRITICAL
- **Status:** FAIL
- **Description:** Lambda function URL is reachable without credentials, enabling unauthenticated invocation, SSRF payload testing, and high-frequency request abuse that can exhaust resources.
- **Remediation:** Require IAM or authorizer-based authentication for function URLs, enforce WAF/rate limiting, and validate inputs to block SSRF-style payloads.

---

### 10. No DLQ Causes Silent Event Loss on Failure (Rule ID: A-LAM-4)
- **Severity:** HIGH
- **Status:** FAIL
- **Description:** Intentional function failures can silently drop events when no dead-letter queue is configured, creating undetected data pipeline gaps and delayed recovery.
- **Remediation:** Configure DLQ or on-failure destinations for asynchronous invocations, alert on retry exhaustion, and monitor end-to-end pipeline lag and drop rates.

---

### 15. Single-AZ RDS Resilience Gap (AZ Failure Downtime) (Rule ID: A-RDS-4)
- **Severity:** HIGH
- **Status:** FAIL
- **Description:** An AZ-level network blackhole on the DB subnet can cause extended downtime when failover is not optimized; this scenario injects AZ disruption, measures outage and failover duration, and compares outcomes with a Multi-AZ baseline.
- **Remediation:** Enable Multi-AZ deployment for production databases, validate automatic failover behavior in regular game days, and set SLOs for failover duration and application reconnect time.

---

### 16. Lateral DB Access from Non-App EC2 Allowed (Rule ID: A-RDS-5)
- **Severity:** HIGH
- **Status:** FAIL
- **Description:** A non-application EC2 instance in the same VPC can connect to the database, indicating weak east-west segmentation; this scenario attempts internal DB access and measures whether AWS Config rules or GuardDuty detections are triggered.
- **Remediation:** Restrict database security group ingress to only approved application security groups, enforce subnet-level segmentation and NACL controls, and implement alerting for anomalous internal database access.

---

### 17. Security Group Should Not Allow 0.0.0.0/0 on SSH/RDP (Rule ID: A-EC2-1)
- **Severity:** CRITICAL
- **Status:** FAIL
- **Description:** Security group allows unrestricted internet access to SSH or RDP which can expose instances to brute force attacks.
- **Remediation:** Restrict SSH/RDP access to trusted IP addresses or use a bastion host or VPN.

#### Chaos Engineering Experiments Conducted
##### Experiment 1: `simulate_brute_force_exposure`
- **Experiment ID:** `33617f5e-3a7a-4ff4-ac64-423b5ced266e`
- **Target ID:** `i-02b1b83ffc67e17ee`
- **Status:** `completed`
- **Impact:** `remote_access_exposure`

**Observations Log:**

| Timestamp | Event | Detail |
| :--- | :--- | :--- |
| `8:04PM` | `pre_snapshot` | target: i-02b1b83ffc67e17ee (35.174.5.109), attempting 10 credential pairs |
| `8:04PM` | `port_confirmed_open` | port 22 is open on 35.174.5.109 — proceeding with brute force |
| `8:04PM` | `attempt_failed` | user=root pass=root → failed (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none], no supported methods remain) |
| `8:04PM` | `attempt_failed` | user=root pass=password → failed (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none], no supported methods remain) |
| `8:04PM` | `attempt_failed` | user=root pass=123456 → failed (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none], no supported methods remain) |
| `8:04PM` | `attempt_failed` | user=admin pass=admin → failed (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none], no supported methods remain) |
| `8:04PM` | `attempt_failed` | user=admin pass=password → failed (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none], no supported methods remain) |
| `8:04PM` | `attempt_failed` | user=ubuntu pass=ubuntu → failed (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none], no supported methods remain) |
| `8:04PM` | `attempt_failed` | user=ec2-user pass=ec2-user → failed (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none], no supported methods remain) |
| `8:04PM` | `attempt_failed` | user=root pass=toor → failed (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none], no supported methods remain) |
| `8:04PM` | `attempt_failed` | user=user pass=user → failed (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none], no supported methods remain) |
| `8:04PM` | `attempt_failed` | user=root pass= → failed (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none], no supported methods remain) |
| `8:04PM` | `finding` | port 22 is exposed to internet but common credentials failed — key-based auth likely enforced |

---

### 18. IMDSv2 Disabled (Rule ID: A-EC2-2)
- **Severity:** HIGH
- **Status:** FAIL
- **Description:** Instance Metadata Service version 2 is not enforced which may allow attackers to steal IAM credentials via SSRF attacks.
- **Remediation:** Enforce IMDSv2 by setting metadata option http_tokens to required.

#### Chaos Engineering Experiments Conducted
##### Experiment 1: `simulate_ssrf_metadata_theft`
- **Experiment ID:** `b0363f42-45ea-4e92-af70-cfca93d917e0`
- **Target ID:** `i-02b1b83ffc67e17ee`
- **Status:** `completed`
- **Impact:** `credential_exposure`

**Observations Log:**

| Timestamp | Event | Detail |
| :--- | :--- | :--- |
| `8:04PM` | `pre_snapshot` | instance i-02b1b83ffc67e17ee has IMDSv2 disabled — metadata endpoint accessible via IMDSv1 |
| `8:04PM` | `ssm_check` | SSM agent available: true |
| `8:04PM` | `iam_credentials_stolen` | iam_credentials_list → retrieved 3 bytes |
| `8:04PM` | `metadata_stolen` | instance_id → retrieved 19 bytes |
| `8:04PM` | `metadata_stolen` | ami_id → retrieved 21 bytes |
| `8:04PM` | `metadata_stolen` | hostname → retrieved 28 bytes |
| `8:05PM` | `metadata_stolen` | public_keys → retrieved 8 bytes |
| `8:05PM` | `metadata_stolen` | user_data → retrieved 906 bytes |
| `8:05PM` | `critical_finding` | CRITICAL: IAM credentials successfully stolen via IMDSv1 — attacker can assume instance role |

---

### 19. EBS Volume Not Encrypted (Rule ID: A-EC2-4)
- **Severity:** MEDIUM
- **Status:** FAIL
- **Description:** EBS volumes are not encrypted which may expose sensitive data if the storage is accessed improperly.
- **Remediation:** Enable encryption for EBS volumes using AWS KMS keys.

#### Chaos Engineering Experiments Conducted
##### Experiment 1: `simulate_ebs_unencrypted_access`
- **Experiment ID:** `82c5cf36-72ac-43c3-8aec-40f94dffa9fd`
- **Target ID:** `vol-0740c9c64859a1d5e`
- **Status:** `completed`
- **Impact:** `data_exposure`

**Observations Log:**

| Timestamp | Event | Detail |
| :--- | :--- | :--- |
| `8:05PM` | `pre_snapshot` | volume vol-0740c9c64859a1d5e — encrypted: false, state: in-use, attached: true |
| `8:05PM` | `attack_started` | volume attached to i-02b1b83ffc67e17ee in us-east-1b — simulating data access via snapshot clone |
| `8:05PM` | `snapshot_created` | snapshot snap-04bf78081cdaafd83 created from unencrypted volume |
| `8:06PM` | `volume_created` | clone volume vol-08b9b4554c1681640 created in us-east-1b |
| `8:06PM` | `volume_attached` | clone volume vol-08b9b4554c1681640 attached to i-02b1b83ffc67e17ee at /dev/xvdz |
| `8:06PM` | `volume_deleted` | volume vol-08b9b4554c1681640 deleted |
| `8:06PM` | `snapshot_deleted` | snapshot snap-04bf78081cdaafd83 deleted |

---

