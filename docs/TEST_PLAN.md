# Master QA & Validation Test Plan — KINETIX

**Created by:** Oscar Emiliano Constanzo Quezada  
**Scope Notice:** Created exclusively for authorized targets.

## 1. Validation Objectives

Empirically certify that the **KINETIX** engine satisfies four strict engineering SLAs prior to deployment in authorized Bug Bounty engagements:

1. **Multidimensional Fingerprinting Accuracy (>= 90%):** Identify exact technology stacks (CPE v2.3) by combining HTTP headers, differential error templates, bounded partial reads (`Range: bytes=0-1023`) on exposed manifests, and lexical extraction of JavaScript bundles via **Dempster-Shafer** evidence fusion, while rejecting false positives caused by SPA catch-all routes (`Soft-404`).
2. **WAF Characterization with Zero False Positives & Zero IP Burn (0% IP Burn Rate):** Identify the WAF vendor and enforcement mode using benign syntactic probes, adjusting request pacing via Gaussian jitter and exponential backoff upon encountering HTTP `429 Too Many Requests`.
3. **Contextual CVE Prioritization Accuracy (`P_exec`):** Distinguish between an exposed vulnerable version (`HIGH`) and the same technology when patched or when its required endpoint/vector is blocked by a reverse proxy or WAF rule (`LOW`).
4. **Zero-Mutation Active Validation (`--enable-poc`):** Guarantee cryptographically that Phase 5 only executes read-only HTTP verbs (`GET`, `HEAD`, `OPTIONS`), caps response reads at `<= 256 bytes`, and leaves the target state checksum (`SHA-256`) unchanged.

---

## 2. Controlled Testbed Architecture (`pkg/testbench`)

The automated benchmark harness launches 6 isolated, instrumented local HTTP servers with real-time state integrity checksums (`StateSHA256`):

| ID | Simulated Environment | Components & Validation Traps | Acceptance Criteria (SLA) |
| :--- | :--- | :--- | :--- |
| **ENV-01** | **OWASP Juice Shop v16.2.1** | Node.js + Express 4.18.2 + Angular 17 SPA + SQLite. Includes a `Soft-404` trap (returns `200 OK` HTML shell for unknown routes), `/assets/public/main.js` containing undocumented routes (`/rest/products/search`, `/api/Users`, `/rest/admin/application-configuration`), and `/ftp/package.json.bak` supporting `Range` requests. | Precision >= 90%, 0 false positives from `Soft-404`, 100% extraction of JS bundle routes. |
| **ENV-02** | **DVWA + ModSecurity CRS 4.0 (PL3)** | Apache 2.4.58 + PHP 8.2 behind ModSecurity in Paranoia Level 3 and an active rate-limiter (`429` trigger). Blocks query-string keywords and encoded traversal, while allowing structured JSON and custom headers. | Exact detection of `modsecurity`, 0 false positives on non-WAF hosts, 0% IP burn (automatic exponential backoff on first `429`), and automatic downgrade of `CVE-2023-38408` to `LOW` (`P_exec = 0.048`). |
| **ENV-03** | **OWASP crAPI (Microservices)** | Go API Gateway + Identity service with a timing side-channel (`+38 ms` on `/identity/api/auth/login` when a valid principal is checked due to simulated password hashing) and parameterized endpoint `/workshop/api/mechanic/receive_report`. | Statistical identification of `svc_mechanic@crapi.local` with `p-value < 0.005` (Welch's t-test) and automatic BOLA edge generation in the attack graph. |
| **ENV-04A** | **Apache OFBiz 18.12.09 (Exposed)** | Vulnerable version `18.12.09` with `/webtools/control/main` reachable and no WAF blocking. | Classified as `HIGH` (`P_exec >= 0.75`) + Verified Zero-Mutation PoC. |
| **ENV-04B** | **Apache OFBiz 18.12.12 (Patched)** | Patched version `18.12.12` with `/webtools/control/main` reachable. | Classified as `LOW` (`P_exec = 0.000`) due to patch detection (`V_match = 0.00`). |
| **ENV-04C** | **Apache OFBiz 18.12.09 (Proxy Blocked)** | Vulnerable version `18.12.09` where `/webtools/control/main` returns `403 Forbidden` at the reverse proxy layer. | Classified as `LOW` (`P_exec = 0.100`) due to surface non-exposure (`E_exp = 0.10`). |

---

## 3. Execution Protocol

### 3.1 Unit & Integration SLA Verification
```powershell
go test -v ./pkg/testbench/...
```

### 3.2 Full Benchmark Execution & Artifact Export
```powershell
go run ./cmd/kinetix --benchmark --out-dir ./artifacts
```

---

## 4. Quantitative Evaluation Metrics

1. **Fingerprinting Precision, Recall, and F1:**
   ```text
   Precision = TP / (TP + FP)
   Recall    = TP / (TP + FN)
   F1        = 2 * (Precision * Recall) / (Precision + Recall)
   ```
2. **Scope Guard Enforcement:**
   * 100% blocking of out-of-scope domains (`external-unscoped.example.org`) and excluded subdomains (`billing.internal.local`) at the `http.RoundTripper` layer.
3. **Zero-Mutation State Audit:**
   * Pre-scan and post-scan `SHA-256` state digests across all 6 servers must remain identical after executing Phase 5 with `--enable-poc`.
