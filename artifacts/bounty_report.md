# KINETIX — Contextual Bug Bounty Triage Report
> **Created by:** Oscar Emiliano Constanzo Quezada | **Notice:** Created exclusively for authorized targets.

## Target Environment: `ENV-01-OWASP-JuiceShop` (http://127.0.0.1:45115)

- **WAF Profile:** Vendor=`none`, Enforcement=`none`, ParanoiaLevel=`0`

### Contextual CVE Prioritization

| CVE ID | Tier | P_exec | Contextual Risk | V_match | W_pass | E_exp | A_viable | Diagnostic / Bottleneck |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CVE-2024-31905** | `HIGH` | `0.997` | `74.8/100` | `1.00` | `1.00` | `1.00` | `1.00` | Exposed endpoint, vulnerable version confirmed, and vector permitted by WAF |

#### Verified Non-Destructive PoC — `CVE-2024-31905`
- **Request:** `GET /rest/products/search?q=apple HTTP/1.1`
- **HTTP Status:** `200` (`59 bytes` read via bounded Range header)
- **Cryptographic Seal (SHA-256):** `8aa7166837579928a7427e25b5bcd178328a6885a05edf19200e4fafdfeed73b`
- **Reproduction Command:**
```bash
curl -i -s -X GET -H 'Range: bytes=0-255' -H 'X-Bug-Bounty: ContextHunter-QA-Verifier' 'http://127.0.0.1:45115/rest/products/search?q=apple'
```
- **Remediation:** Parameterize search queries and disable public access to /ftp/*.bak backup manifests.

## Target Environment: `ENV-02-DVWA-ModSecurity-PL3` (http://127.0.0.1:45116)

- **WAF Profile:** Vendor=`modsecurity`, Enforcement=`block_immediate`, ParanoiaLevel=`3`

### Contextual CVE Prioritization

| CVE ID | Tier | P_exec | Contextual Risk | V_match | W_pass | E_exp | A_viable | Diagnostic / Bottleneck |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CVE-2023-38408** | `LOW` | `0.048` | `4.2/100` | `0.95` | `0.05` | `1.00` | `1.00` | Blocked by WAF (modsecurity) on vector query_string_sqli_keywords (W_pass=0.05) |

## Target Environment: `ENV-03-OWASP-crAPI` (http://127.0.0.1:45117)

- **WAF Profile:** Vendor=`none`, Enforcement=`none`, ParanoiaLevel=`0`
- **Enumerated Identity:** `svc_mechanic@crapi.local` via `timing_oracle_welch_t` (Mean Latency: `38.69 ms` vs Baseline `2.86 ms`, Welch's `t = 73.93`, Confidence: `0.96`)

### Contextual CVE Prioritization

| CVE ID | Tier | P_exec | Contextual Risk | V_match | W_pass | E_exp | A_viable | Diagnostic / Bottleneck |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CVE-2024-29847** | `HIGH` | `0.956` | `77.4/100` | `1.00` | `1.00` | `1.00` | `0.96` | Exposed endpoint, vulnerable version confirmed, and vector permitted by WAF |

#### Verified Non-Destructive PoC — `CVE-2024-29847`
- **Request:** `GET /workshop/api/mechanic/receive_report?report_id=1 HTTP/1.1`
- **HTTP Status:** `206` (`70 bytes` read via bounded Range header)
- **Cryptographic Seal (SHA-256):** `3ab265f57cd111ab07cee898afe2d6512d60f42ba50eb523b1f38faacc0ec1a0`
- **Reproduction Command:**
```bash
curl -i -s -X GET -H 'Range: bytes=0-255' -H 'X-Bug-Bounty: ContextHunter-QA-Verifier' 'http://127.0.0.1:45117/workshop/api/mechanic/receive_report?report_id=1'
```
- **Remediation:** Enforce object-level ownership checks comparing JWT subject against report owner ID.

## Target Environment: `ENV-04A-OFBiz-18.12.09-Exposed` (http://127.0.0.1:45118)

- **WAF Profile:** Vendor=`none`, Enforcement=`none`, ParanoiaLevel=`0`

### Contextual CVE Prioritization

| CVE ID | Tier | P_exec | Contextual Risk | V_match | W_pass | E_exp | A_viable | Diagnostic / Bottleneck |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CVE-2023-51467** | `HIGH` | `0.998` | `97.8/100` | `1.00` | `1.00` | `1.00` | `1.00` | Exposed endpoint, vulnerable version confirmed, and vector permitted by WAF |

#### Verified Non-Destructive PoC — `CVE-2023-51467`
- **Request:** `GET /webtools/control/main?ctx_verify=1 HTTP/1.1`
- **HTTP Status:** `206` (`82 bytes` read via bounded Range header)
- **Cryptographic Seal (SHA-256):** `6b6fcf3128cae1fc88dd897534aa8fe048c35a4fb8a1d5d508573ae95edeef11`
- **Reproduction Command:**
```bash
curl -i -s -X GET -H 'Range: bytes=0-255' -H 'X-Bug-Bounty: ContextHunter-QA-Verifier' 'http://127.0.0.1:45118/webtools/control/main?ctx_verify=1'
```
- **Remediation:** Upgrade Apache OFBiz to >= 18.12.12 and restrict /webtools/* at the reverse proxy layer.

## Target Environment: `ENV-04B-OFBiz-18.12.12-Patched` (http://127.0.0.1:45119)

- **WAF Profile:** Vendor=`none`, Enforcement=`none`, ParanoiaLevel=`0`

### Contextual CVE Prioritization

| CVE ID | Tier | P_exec | Contextual Risk | V_match | W_pass | E_exp | A_viable | Diagnostic / Bottleneck |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CVE-2023-51467** | `LOW` | `0.000` | `0.0/100` | `0.00` | `0.00` | `0.00` | `0.00` | Patched version detected (cpe:2.3:a:apache:ofbiz:18.12.12:*:*:*:*:*:*:*, conf=1.00) |

## Target Environment: `ENV-04C-OFBiz-18.12.09-ProxyBlocked` (http://127.0.0.1:45120)

- **WAF Profile:** Vendor=`none`, Enforcement=`none`, ParanoiaLevel=`0`

### Contextual CVE Prioritization

| CVE ID | Tier | P_exec | Contextual Risk | V_match | W_pass | E_exp | A_viable | Diagnostic / Bottleneck |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CVE-2023-51467** | `LOW` | `0.100` | `9.8/100` | `1.00` | `1.00` | `0.10` | `1.00` | Required endpoint /webtools/control/main is not exposed or blocked (403/404) |

