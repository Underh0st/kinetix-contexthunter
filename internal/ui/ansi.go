// language: Go, file: internal/ui/ansi.go, target: Go 1.22+, Cross-Platform
package ui

import (
	"fmt"
	"strings"

	"github.com/Underh0st/kinetix-contexthunter/internal/correlator"
	"github.com/Underh0st/kinetix-contexthunter/internal/enumerator"
	"github.com/Underh0st/kinetix-contexthunter/internal/fingerprint"
	"github.com/Underh0st/kinetix-contexthunter/internal/scope"
	"github.com/Underh0st/kinetix-contexthunter/internal/validator"
	"github.com/Underh0st/kinetix-contexthunter/internal/waf"
	"github.com/Underh0st/kinetix-contexthunter/pkg/testbench"
)

const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[97m"
	Gray    = "\033[90m"
)

type Console struct {
	NoColor bool
}

func NewConsole(noColor bool) *Console {
	return &Console{NoColor: noColor}
}

func (c *Console) c(code, text string) string {
	if c.NoColor || code == "" {
		return text
	}
	return code + text + Reset
}

// pad pads the visible text to width first, then wraps it in ANSI color codes so columns align.
func (c *Console) pad(width int, code, text string) string {
	padded := fmt.Sprintf("%-*s", width, text)
	return c.c(code, padded)
}

func (c *Console) PrintBanner() {
	banner := `
+------------------------------------------------------------------------------+
|  _  ___ _   _ _____ _____ _____ __  __                                       |
| | |/ /_ _| \ | | ____|_   _|_ _\ \/ /   KINETIX ENGINE v1.0.0                |
| | ' / | ||  \| |  _|   | |  | | \  /    Created by:                          |
| | . \ | || |\  | |___  | |  | | /  \    Oscar Emiliano Constanzo Quezada     |
| |_|\_\___|_| \_|_____| |_| |___/_/\_\   [Created Only for Authorized Targets]|
+------------------------------------------------------------------------------+`
	fmt.Println(c.c(Bold+Cyan, banner))
}

func (c *Console) PrintSection(phase, title string) {
	line := strings.Repeat("-", 78)
	fmt.Printf("\n%s\n", c.c(Gray, line))
	fmt.Printf("%s %s\n", c.c(Bold+Cyan, "["+phase+"]"), c.c(Bold+White, title))
	fmt.Printf("%s\n", c.c(Gray, line))
}

func (c *Console) PrintScopeConfig(targetURL string, p scope.Policy) {
	c.PrintSection("PHASE 0", "STRICT SCOPE INTERCEPTOR & STEALTH TRANSPORT")
	fmt.Printf("  %s : %s\n", c.pad(22, Gray, "Normalized Target"), c.c(Bold+White, targetURL))
	fmt.Printf("  %s : %s\n", c.pad(22, Gray, "Allowed Hosts"), c.c(Green, strings.Join(p.AllowedHosts, ", ")))
	fmt.Printf("  %s : %.1f req/s (Gaussian jitter: %.1f ms, Max backoff: %.0f ms)\n",
		c.pad(22, Gray, "Rate Pacing"), p.MaxRPS, p.BaseJitterMs, p.MaxBackoffMs)
}

func (c *Console) PrintFingerprint(fp *fingerprint.Result) {
	c.PrintSection("PHASE 1", "MULTIDIMENSIONAL FINGERPRINTING (DEMPSTER-SHAFER FUSION)")
	soft404Status := c.c(Green, "Disabled / Standard 404")
	if fp.HasSoft404 {
		soft404Status = c.c(Yellow, fmt.Sprintf("Detected SPA Catch-All (SHA256: %s...)", fp.Soft404Hash[:12]))
	}
	fmt.Printf("  %s : %s\n\n", c.pad(22, Gray, "Soft-404 Calibration"), soft404Status)

	fmt.Printf("  %s | %s | %s\n",
		c.pad(50, Bold+White, "DETECTED CPE v2.3"),
		c.pad(10, Bold+White, "CONFIDENCE"),
		c.pad(12, Bold+White, "STATUS"))
	fmt.Printf("  %s\n", c.c(Gray, strings.Repeat("-", 78)))
	if len(fp.CombinedCPEs) == 0 {
		fmt.Printf("  %s\n", c.c(Gray, "No explicit CPE signatures detected."))
	}
	for cpe, conf := range fp.CombinedCPEs {
		fmt.Printf("  %-50s | %-10.3f | %s\n", cpe, conf, c.c(Green, "CONFIRMED"))
	}
	if len(fp.DiscoveredRoutes) > 0 {
		fmt.Printf("\n  %s (%d): %s\n", c.c(Gray, "Extracted JS AST Routes"), len(fp.DiscoveredRoutes), c.c(Cyan, strings.Join(fp.DiscoveredRoutes, ", ")))
	}
}

func (c *Console) PrintWAF(w *waf.Profile) {
	c.PrintSection("PHASE 2", "WAF CHARACTERIZATION & PERMISSIVENESS MATRIX")
	vendorStr := c.c(Green, "none (Direct Backend Exposure)")
	if w.Detected {
		vendorStr = c.c(Yellow, fmt.Sprintf("%s (Mode: %s, Paranoia Level: %d)", w.Vendor, w.EnforcementMode, w.ParanoiaLevel))
	}
	fmt.Printf("  %s : %s\n\n", c.pad(22, Gray, "Detected Filter/WAF"), vendorStr)
	fmt.Printf("  %s | %s | %s\n",
		c.pad(38, Bold+White, "VECTOR CHANNEL"),
		c.pad(12, Bold+White, "W_pass SCORE"),
		c.pad(18, Bold+White, "FILTER POSTURE"))
	fmt.Printf("  %s\n", c.c(Gray, strings.Repeat("-", 74)))
	for vec, score := range w.PermissivenessMatrix {
		posture := c.c(Green, "PERMISSIVE")
		if score < 0.25 {
			posture = c.c(Red, "BLOCKED (403)")
		} else if score < 0.70 {
			posture = c.c(Yellow, "INSPECTED")
		}
		fmt.Printf("  %-38s | %-12.2f | %s\n", string(vec), score, posture)
	}
}

func (c *Console) PrintEnumeration(en *enumerator.EnumerationResult) {
	c.PrintSection("PHASE 4", "API SURFACE & STATISTICAL IDENTITY ORACLE (WELCH'S T-TEST)")
	fmt.Printf("  %s | %s | %s\n",
		c.pad(44, Bold+White, "DISCOVERED ENDPOINT"),
		c.pad(12, Bold+White, "HTTP STATUS"),
		c.pad(14, Bold+White, "SURFACE STATE"))
	fmt.Printf("  %s\n", c.c(Gray, strings.Repeat("-", 76)))
	for ep, st := range en.ExposedEndpoints {
		if st == 404 {
			continue
		}
		state := c.c(Gray, "UNREACHABLE (404)")
		if st >= 200 && st < 300 {
			state = c.c(Green, "EXPOSED (2xx)")
		} else if st == 401 || st == 405 {
			state = c.c(Cyan, "AUTH/CTRL (4xx)")
		} else if st == 403 {
			state = c.c(Red, "ACL BLOCKED")
		}
		fmt.Printf("  %-44s | %-12d | %s\n", ep, st, state)
	}

	if len(en.ValidPrincipals) > 0 {
		fmt.Printf("\n  %s\n", c.c(Bold+White, "Enumerated Principals via Timing Oracle:"))
		for _, p := range en.ValidPrincipals {
			fmt.Printf("    -> %s | Mean: %.2fms vs Base: %.2fms | Welch's t=%.2f | Conf=%.2f\n",
				c.c(Bold+Cyan, p.Identifier), p.MeanLatencyMs, p.BaselineMs, p.TStatistic, p.Confidence)
		}
	}
}

func (c *Console) PrintFindings(findings []correlator.ContextualFinding, evidences map[string]*validator.Evidence) {
	c.PrintSection("PHASE 3 & 5", "CONTEXTUAL CVE CORRELATION & ZERO-MUTATION VALIDATION")
	fmt.Printf("  %s | %s | %s | %s | %s\n",
		c.pad(16, Bold+White, "CVE ID"),
		c.pad(8, Bold+White, "TIER"),
		c.pad(7, Bold+White, "P_exec"),
		c.pad(7, Bold+White, "RISK"),
		c.pad(34, Bold+White, "DIAGNOSTIC / BOTTLENECK"))
	fmt.Printf("  %s\n", c.c(Gray, strings.Repeat("-", 84)))

	shown := 0
	for _, f := range findings {
		if f.FactorBreakdown["V_match"] == 0 && !strings.Contains(f.BottleneckReason, "Patched") {
			continue
		}
		shown++
		tierColor := Gray
		if f.Tier == "HIGH" {
			tierColor = Bold + Red
		} else if f.Tier == "MEDIUM" {
			tierColor = Bold + Yellow
		}
		fmt.Printf("  %-16s | %s | %-7.3f | %-7.1f | %s\n",
			f.CVEID, c.pad(8, tierColor, f.Tier), f.ProbabilityScore, f.ContextualRisk, f.BottleneckReason)
		fmt.Printf("    %s %s (Endpoint: %s)\n",
			c.c(Bold+Yellow, "[VULN VECTOR]  "), c.c(Bold+White, f.Title), c.c(Cyan, f.Endpoint))

		if ev, ok := evidences[f.CVEID]; ok && ev != nil && ev.Validated {
			fmt.Printf("    %s Request: %s -> Status %d (%d bytes read)\n",
				c.c(Bold+Green, "[POC VERIFIED] "), ev.RequestLine, ev.StatusCode, ev.BytesRead)
			fmt.Printf("    %s SHA-256: %s\n", c.c(Gray, "[EVIDENCE SEAL]"), c.c(Cyan, ev.EvidenceSHA256))
			fmt.Printf("    %s %s\n", c.c(Gray, "[REPRO COMMAND]"), ev.ReproCurl)
		}
	}
	if shown == 0 {
		fmt.Printf("  %s\n", c.c(Gray, "No matching CVEs in local catalog for detected stack."))
	}
}

func (c *Console) PrintBenchmarkSummary(s *testbench.BenchmarkSummary, outDir string) {
	c.PrintSection("QA BENCHMARK", "6-ENVIRONMENT AUTOMATED VALIDATION MATRIX")
	fmt.Printf("  %s | %s | %s | %s | %s\n",
		c.pad(10, Bold+White, "ENV ID"),
		c.pad(28, Bold+White, "SIMULATED TARGET"),
		c.pad(11, Bold+White, "WAF"),
		c.pad(35, Bold+White, "CONTEXTUAL CVE SCORE"),
		c.pad(10, Bold+White, "STATE HASH"))
	fmt.Printf("  %s\n", c.c(Gray, strings.Repeat("-", 106)))

	for _, e := range s.EnvironmentDetails {
		parts := strings.SplitN(e.Environment, "-", 3)
		envID := e.Environment
		envName := e.Environment
		if len(parts) >= 3 {
			envID = parts[0] + "-" + parts[1]
			envName = parts[2]
		}
		cveSummary := ""
		for k, v := range e.EvaluatedCVEs {
			cveSummary = fmt.Sprintf("%s: %s", k, v)
		}
		hashStatus := c.c(Green, "IMMUTABLE")
		if e.StateHashBefore != e.StateHashAfter {
			hashStatus = c.c(Red, "MUTATED")
		}
		fmt.Printf("  %s | %-28s | %-11s | %-35s | %s\n",
			c.pad(10, Cyan, envID), envName, e.WAFVendor, cveSummary, hashStatus)
	}

	c.PrintSection("SLA METRICS", "QUANTITATIVE ENGINE EVALUATION")
	fmt.Printf("  %-34s : %s (TP=%d, FP=%d, FN=%d)\n",
		"Fingerprinting Precision / Recall",
		c.c(Bold+Green, fmt.Sprintf("%.1f%% / %.1f%% (F1=%.1f%%)", s.FingerprintPrecision*100, s.FingerprintRecall*100, s.FingerprintF1*100)),
		s.TruePositivesCPE, s.FalsePositivesCPE, s.FalseNegativesCPE)
	fmt.Printf("  %-34s : %s (False Positives: %d)\n",
		"WAF Classification Accuracy",
		c.c(Bold+Green, fmt.Sprintf("%.1f%%", s.WAFDetectionAccuracy*100)),
		s.WAFFalsePositives)
	fmt.Printf("  %-34s : %s (%d/%d scenarios matched)\n",
		"Contextual CVE Tier Accuracy",
		c.c(Bold+Green, fmt.Sprintf("%.1f%%", s.ContextualAccuracy*100)),
		s.ContextualTierMatches, s.ContextualTierTotal)
	fmt.Printf("  %-34s : %s (Out-of-Scope Blocked: %d, 429 Backoffs: %d)\n",
		"Transport Guard & Zero-Mutation",
		c.c(Bold+Green, fmt.Sprintf("VERIFIED (IP Burn: %d)", s.IPBurnCount)),
		s.ScopeViolationsBlocked, s.RateLimitBackoffs)
	fmt.Printf("\n  %s %s\n", c.c(Bold+Cyan, "[ARTIFACTS EXPORTED]"), c.c(White, outDir))
}
