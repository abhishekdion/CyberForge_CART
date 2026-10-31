# CyberForge CART Assessment Report: `run_be9cdef7dc40`

**Generated:** 2026-10-31T15:45:29+00:00  
**Run Status:** `PARTIAL` | **Tier:** `recon`  
**Started:** 2026-10-31T15:45:25+00:00 | **Completed:** 2026-10-31T15:45:29+00:00  

## 1. Executive Summary

Assessment run run_be9cdef7dc40 (PARTIAL) discovered 1 asset(s) and 2 open service(s). Identified 0 finding(s) with 0 confirmed. Scope safety enforced 3 out-of-scope denials with 0 safety leaks.

## 2. PRD Assessment Metrics

| Measure | Target | Actual Result | Status |
|---|---|---|---|
| **Scope Safety** | 0 out-of-scope probes | **0 leaks** (3 denied by gate) | ✅ PASS |
| **Autonomy** | 0 human interventions post-start | **0 interventions** | ✅ PASS |
| **Verification Rate** | > 85% | **100.0%** (0 confirmed) | ✅ PASS |
| **False Alarms** | < 10% | **0.0%** | ✅ PASS |
| **Run Duration** | < 1200 s (20 min) | **4.0 s** | ✅ PASS |

## 3. Scope & Authority

- **Manifest Version:** `scope_dc2572297521`
- **Locked At:** `2026-10-31T15:45:21+00:00`
- **Included Prefixes:** `127.0.0.1/32`
- **Included Hosts:** `None`
- **Exclusions:** `None`
- **Registered Binaries:** `0 registered`

## 4. Discovered Assets & Services

| Asset Key | Type | Open Ports / Services | First Seen |
|---|---|---|---|
| `127.0.0.1` | `host` | 135/tcp (msrpc), 445/tcp (microsoft-ds) | 2026-10-31T15:45:26+00:00 |

## 5. Findings & Weakness Analysis

_No findings identified in this run._

## 6. Evidence-Backed Attack Paths

_No evidence-backed lateral attack paths found._

---
_Report generated autonomously by CyberForge CART._