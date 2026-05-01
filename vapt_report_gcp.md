# Vulnerability Assessment & Penetration Testing (VAPT) Report
**Date:** Fri, 01 May 2026 15:44:41 IST

## Executive Summary
This report summarizes the results of an automated security audit and subsequent chaos engineering experiments. It details identified vulnerabilities, misconfigurations, and validated exploits alongside detailed experiment tracking.

### Summary Statistics
- **Total Rules Evaluated:** 5
- **Passed:** 1
- **Failed:** 4
- **Error:** 0

## Detailed Findings with Verified Exploit Testing

### 1. Primitive Roles (Owner/Editor) Assigned to Users (Rule ID: G-IAM-1)
- **Severity:** CRITICAL
- **Status:** FAIL
- **Description:** Basic roles (roles/owner, roles/editor) grant far broader permissions than needed and violate the principle of least-privilege at project level. Any user or service account holding one of these roles can read, write, and delete most GCP resources in the project without restriction.

- **Remediation:** Replace roles/owner and roles/editor with purpose-built predefined roles (e.g. roles/storage.objectAdmin for GCS access). Use IAM Conditions to restrict scope by resource or time. Review bindings quarterly via IAM Recommender.


---

### 2. Service Account Key File Downloaded and Stored (Rule ID: G-IAM-2)
- **Severity:** HIGH
- **Status:** FAIL
- **Description:** A USER_MANAGED service account key (exported JSON) exists. These keys can be downloaded and used indefinitely — GCP does not automatically rotate them. A leaked key allows an attacker to authenticate as the service account from anywhere in the world without expiry.

- **Remediation:** Delete all USER_MANAGED SA keys and use Workload Identity Federation or the Attached Service Account mechanism instead. If a key is absolutely required, enforce a 90-day maximum age via an Org Policy constraint (iam.disableServiceAccountKeyCreation is preferred) and rotate regularly.


---

### 3. Service Account Has Project-Level Admin Role (Rule ID: G-IAM-3)
- **Severity:** CRITICAL
- **Status:** FAIL
- **Description:** A service account is bound to a highly privileged role (roles/owner, roles/editor, roles/iam.serviceAccountAdmin, etc.) at project scope. If the workload using this SA is compromised, the attacker obtains project-wide administrative access.

- **Remediation:** Assign granular predefined roles scoped to the specific resource the workload needs. Prefer Workload Identity so Kubernetes/Cloud Run workloads inherit short-lived credentials. Audit via `gcloud projects get-iam-policy <PROJECT>` and remove over-provisioned bindings.


---

### 4. Cross-Project IAM Binding Without Justification (Rule ID: G-IAM-4)
- **Severity:** HIGH
- **Status:** FAIL
- **Description:** An IAM policy on this project grants access to a service account whose email belongs to a DIFFERENT GCP project. Without documented justification and compensating controls this creates a lateral-movement path: compromising the foreign project pivots directly into this project's resources.

- **Remediation:** Audit all IAM bindings for external service accounts with `gcloud projects get-iam-policy`. Remove cross-project bindings that lack a documented business justification. Use VPC Service Controls to restrict cross-project API access. Prefer Workload Identity Federation for cross-project authentication flows.


---

## Chaos Engineering Experiments

### Experiment 1: simulate_owner_role_abuse

**Related Finding:** Primitive Roles (Owner/Editor) Assigned to Users (Rule ID: G-IAM-1)

• **Experiment ID:** G-IAM-1-sim
• **Target ID:** 
• **Status:** SIMULATED
• **Impact:** An identity with roles/owner can enumerate all resources, delete IAM bindings, exfiltrate secrets, and escalate privileges across the entire project without restriction.

---

### Experiment 2: simulate_owner_role_abuse

**Related Finding:** Service Account Key File Downloaded and Stored (Rule ID: G-IAM-2)

• **Experiment ID:** G-IAM-1-sim
• **Target ID:** 
• **Status:** SIMULATED
• **Impact:** An identity with roles/owner can enumerate all resources, delete IAM bindings, exfiltrate secrets, and escalate privileges across the entire project without restriction.

---

### Experiment 3: simulate_workload_privilege_escalation

**Related Finding:** Service Account Has Project-Level Admin Role (Rule ID: G-IAM-3)

• **Experiment ID:** G-IAM-3-sim
• **Target ID:** 
• **Status:** SIMULATED
• **Impact:** A workload (e.g. Cloud Run, GKE Pod) bound to a SA with roles/editor or roles/owner can call any GCP API. If the workload is compromised, the attacker inherits project-wide admin privileges.

---

### Experiment 4: simulate_workload_privilege_escalation

**Related Finding:** Cross-Project IAM Binding Without Justification (Rule ID: G-IAM-4)

• **Experiment ID:** G-IAM-3-sim
• **Target ID:** 
• **Status:** SIMULATED
• **Impact:** A workload (e.g. Cloud Run, GKE Pod) bound to a SA with roles/editor or roles/owner can call any GCP API. If the workload is compromised, the attacker inherits project-wide admin privileges.

---

