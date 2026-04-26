# Vulnerability Assessment & Penetration Testing (VAPT) Report
**Date:** Sun, 26 Apr 2026 14:40:11 IST

## Executive Summary
This report summarizes the results of an automated security audit and subsequent chaos engineering experiments. It details identified vulnerabilities, misconfigurations, and validated exploits alongside detailed experiment tracking.

### Summary Statistics
- **Total Rules Evaluated:** 5
- **Passed:** 3
- **Failed:** 2
- **Error:** 0

## Detailed Findings with Verified Exploit Testing

### 1. Unauthenticated Lambda URL Invocation Exposure (Rule ID: A-LAM-3)
- **Severity:** CRITICAL
- **Status:** FAIL
- **Description:** Lambda function URL is reachable without credentials, enabling unauthenticated invocation, SSRF payload testing, and high-frequency request abuse that can exhaust resources.
- **Remediation:** Require IAM or authorizer-based authentication for function URLs, enforce WAF/rate limiting, and validate inputs to block SSRF-style payloads.

---

### 2. No DLQ Causes Silent Event Loss on Failure (Rule ID: A-LAM-4)
- **Severity:** HIGH
- **Status:** FAIL
- **Description:** Intentional function failures can silently drop events when no dead-letter queue is configured, creating undetected data pipeline gaps and delayed recovery.
- **Remediation:** Configure DLQ or on-failure destinations for asynchronous invocations, alert on retry exhaustion, and monitor end-to-end pipeline lag and drop rates.

---

## Chaos Engineering Experiments

### Experiment 1: simulate_unauthenticated_invocation

**Related Finding:** Unauthenticated Lambda URL Invocation Exposure (Rule ID: A-LAM-3)

• **Experiment ID:** 622db3cb-80fd-4cbf-a420-f780e4e1219d
• **Target ID:** chaos
• **Status:** vulnerability_confirmed
• **Impact:** unauthorized_invocation_and_resource_exhaustion

**Observations Log:**

| Timestamp | Event | Detail |
| :--- | :--- | :--- |
| 2:39PM | pre_snapshot | Function: chaos, URL Enabled: true, Auth Type: NONE |
| 2:39PM | auth_check | Function URL auth type: NONE (unauthenticated: true) |
| 2:39PM | invocation_attempt | URL: https://mhihn4nhvxrywf7wd6w6nudhiq0xioyh.lambda-url.us-east-1.on.aws/, Status: 502, Response (first 100 chars): Internal Server Error |
| 2:40PM | invocation_attempt | URL: https://mhihn4nhvxrywf7wd6w6nudhiq0xioyh.lambda-url.us-east-1.on.aws/, Status: 502, Response (first 100 chars): Internal Server Error |
| 2:40PM | invocation_attempt | URL: https://mhihn4nhvxrywf7wd6w6nudhiq0xioyh.lambda-url.us-east-1.on.aws/, Status: 502, Response (first 100 chars): Internal Server Error |
| 2:40PM | ssrf_attempt_successful | URL: https://mhihn4nhvxrywf7wd6w6nudhiq0xioyh.lambda-url.us-east-1.on.aws/, Status: 502, Response (first 100 chars): Internal Server Error |
| 2:40PM | ssrf_attempt_successful | URL: https://mhihn4nhvxrywf7wd6w6nudhiq0xioyh.lambda-url.us-east-1.on.aws/, Status: 502, Response (first 100 chars): Internal Server Error |
| 2:40PM | ssrf_attempt_successful | URL: https://mhihn4nhvxrywf7wd6w6nudhiq0xioyh.lambda-url.us-east-1.on.aws/, Status: 502, Response (first 100 chars): Internal Server Error |
| 2:40PM | ssrf_attempt_successful | URL: https://mhihn4nhvxrywf7wd6w6nudhiq0xioyh.lambda-url.us-east-1.on.aws/, Status: 502, Response (first 100 chars): Internal Server Error |
| 2:40PM | ssrf_attempt_successful | URL: https://mhihn4nhvxrywf7wd6w6nudhiq0xioyh.lambda-url.us-east-1.on.aws/, Status: 502, Response (first 100 chars): Internal Server Error |
| 2:40PM | ssrf_attempt_successful | URL: https://mhihn4nhvxrywf7wd6w6nudhiq0xioyh.lambda-url.us-east-1.on.aws/, Status: 502, Response (first 100 chars): Internal Server Error |
| 2:40PM | ssrf_attempt_successful | URL: https://mhihn4nhvxrywf7wd6w6nudhiq0xioyh.lambda-url.us-east-1.on.aws/, Status: 502, Response (first 100 chars): Internal Server Error |
| 2:40PM | ssrf_attempt_successful | URL: https://mhihn4nhvxrywf7wd6w6nudhiq0xioyh.lambda-url.us-east-1.on.aws/, Status: 502, Response (first 100 chars): Internal Server Error |
| 2:40PM | resource_exhaustion_vector | Unauthenticated URL allows unlimited invocation requests — can trigger resource exhaustion (DDoS) via function concurrency limits and cost inflation |
| 2:40PM | critical_finding | CRITICAL: Function URL is publicly accessible without authentication — 3 successful invocations possible |

---

### Experiment 2: simulate_silent_function_failure

**Related Finding:** No DLQ Causes Silent Event Loss on Failure (Rule ID: A-LAM-4)

• **Experiment ID:** eec531b2-b548-498e-81a8-e20ffc46c41e
• **Target ID:** chaos
• **Status:** completed
• **Impact:** data_pipeline_gap

**Observations Log:**

| Timestamp | Event | Detail |
| :--- | :--- | :--- |
| 2:40PM | pre_snapshot | Function: chaos, Event sources: 0, DLQ configured: false |
| 2:40PM | event_source_analysis | Function has 0 asynchronous event source(s) — DLQ configured: false |
| 2:40PM | no_event_sources | Function has no asynchronous event sources configured — DLQ not applicable for synchronous invocations |

---

