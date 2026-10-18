// language: Go, file: internal/graph/exporter.go, target: Go 1.22+, Cross-Platform
package graph

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Underh0st/kinetix-contexthunter/internal/correlator"
	"github.com/Underh0st/kinetix-contexthunter/internal/enumerator"
	"github.com/Underh0st/kinetix-contexthunter/internal/fingerprint"
	"github.com/Underh0st/kinetix-contexthunter/internal/validator"
	"github.com/Underh0st/kinetix-contexthunter/internal/waf"
)

type Node struct {
	ID         string  `json:"id"`
	Type       string  `json:"type"`
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"`
	Tier       string  `json:"tier,omitempty"`
}

type Edge struct {
	Source   string  `json:"source"`
	Target   string  `json:"target"`
	Relation string  `json:"relation"`
	Weight   float64 `json:"weight"`
}

type AttackGraph struct {
	Engine      string `json:"engine"`
	GeneratedAt string `json:"generated_at"`
	Nodes       []Node `json:"nodes"`
	Edges       []Edge `json:"edges"`
}

type TargetBundle struct {
	Name        string
	Fingerprint *fingerprint.Result
	WAF         *waf.Profile
	Enumeration *enumerator.EnumerationResult
	Findings    []correlator.ContextualFinding
	Evidences   map[string]*validator.Evidence // CVEID -> Evidence
}

// BuildGraph constructs the unified AttackGraph across all evaluated targets.
func BuildGraph(bundles []TargetBundle) AttackGraph {
	g := AttackGraph{
		Engine:      "ContextHunter/KINETIX v1.0.0",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	for idx, b := range bundles {
		prefix := fmt.Sprintf("t%d", idx+1)
		wafNodeID := prefix + "_waf"
		wafLabel := "WAF: none"
		if b.WAF != nil && b.WAF.Detected {
			wafLabel = fmt.Sprintf("WAF: %s (mode=%s, PL=%d)", b.WAF.Vendor, b.WAF.EnforcementMode, b.WAF.ParanoiaLevel)
		}
		g.Nodes = append(g.Nodes, Node{
			ID:         wafNodeID,
			Type:       "WAF_PROFILE",
			Label:      fmt.Sprintf("[%s] %s", b.Name, wafLabel),
			Confidence: 0.99,
		})

		// Principal nodes
		if b.Enumeration != nil {
			for pIdx, p := range b.Enumeration.ValidPrincipals {
				pNodeID := fmt.Sprintf("%s_user_%d", prefix, pIdx+1)
				g.Nodes = append(g.Nodes, Node{
					ID:         pNodeID,
					Type:       "ENUMERATED_PRINCIPAL",
					Label:      fmt.Sprintf("[%s] Identity: %s (t=%.2f, mean=%.1fms)", b.Name, p.Identifier, p.TStatistic, p.MeanLatencyMs),
					Confidence: p.Confidence,
				})
				for _, bind := range b.Enumeration.Bindings {
					if bind.PrincipalID == p.Identifier {
						epNodeID := fmt.Sprintf("%s_ep_%s", prefix, sanitizeID(bind.Endpoint))
						g.Edges = append(g.Edges, Edge{
							Source:   pNodeID,
							Target:   epNodeID,
							Relation: "ENABLES_AUTHENTICATED_OR_BOLA_VECTOR",
							Weight:   bind.Confidence,
						})
					}
				}
			}
		}

		// Findings, Tech, Endpoint, and PoC nodes
		for fIdx, f := range b.Findings {
			if f.ProbabilityScore <= 0 && f.Tier == "LOW" && f.FactorBreakdown["V_match"] == 0 && !strings.Contains(f.BottleneckReason, "Patched") {
				continue
			}
			techID := fmt.Sprintf("%s_tech_%d", prefix, fIdx+1)
			epID := fmt.Sprintf("%s_ep_%s", prefix, sanitizeID(f.Endpoint))
			cveID := fmt.Sprintf("%s_cve_%s", prefix, sanitizeID(f.CVEID))

			g.Nodes = append(g.Nodes,
				Node{
					ID:         techID,
					Type:       "TECH_FINGERPRINT",
					Label:      fmt.Sprintf("[%s] %s", b.Name, f.AffectedCPE),
					Confidence: f.FactorBreakdown["V_match"],
				},
				Node{
					ID:         epID,
					Type:       "API_ENDPOINT",
					Label:      fmt.Sprintf("[%s] %s", b.Name, f.Endpoint),
					Confidence: f.FactorBreakdown["E_exp"],
				},
				Node{
					ID:         cveID,
					Type:       "CONTEXTUAL_CVE",
					Label:      fmt.Sprintf("[%s] %s (P_exec=%.2f, Tier=%s)", b.Name, f.CVEID, f.ProbabilityScore, f.Tier),
					Confidence: f.ProbabilityScore,
					Tier:       f.Tier,
				},
			)

			g.Edges = append(g.Edges,
				Edge{Source: techID, Target: cveID, Relation: "VERSION_MATCH", Weight: f.FactorBreakdown["V_match"]},
				Edge{Source: wafNodeID, Target: cveID, Relation: "WAF_PERMEABILITY", Weight: f.FactorBreakdown["W_pass"]},
				Edge{Source: epID, Target: cveID, Relation: "EXPOSES_ENDPOINT", Weight: f.FactorBreakdown["E_exp"]},
			)

			if ev, ok := b.Evidences[f.CVEID]; ok && ev != nil && ev.Validated {
				pocID := fmt.Sprintf("%s_poc_%s", prefix, sanitizeID(f.CVEID))
				g.Nodes = append(g.Nodes, Node{
					ID:         pocID,
					Type:       "VALIDATED_POC",
					Label:      fmt.Sprintf("[%s] PoC Verified (%d, %dB, SHA256:%s...)", b.Name, ev.StatusCode, ev.BytesRead, ev.EvidenceSHA256[:12]),
					Confidence: 1.0,
					Tier:       "VERIFIED",
				})
				g.Edges = append(g.Edges, Edge{
					Source:   cveID,
					Target:   pocID,
					Relation: "ZERO_MUTATION_VERIFIED",
					Weight:   1.0,
				})
			}
		}
	}

	return g
}

func ExportAll(outDir string, bundles []TargetBundle, g AttackGraph) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	// 1. Export JSON Graph
	jsonBytes, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "attack_graph.json"), jsonBytes, 0644); err != nil {
		return err
	}

	// 2. Export Graphviz DOT
	dotContent := renderDOT(g)
	if err := os.WriteFile(filepath.Join(outDir, "attack_graph.dot"), []byte(dotContent), 0644); err != nil {
		return err
	}

	// 3. Export HackerOne / Bugcrowd Markdown Report
	mdContent := renderBountyMarkdown(bundles)
	if err := os.WriteFile(filepath.Join(outDir, "bounty_report.md"), []byte(mdContent), 0644); err != nil {
		return err
	}

	// 4. Export Interactive HTML Report
	htmlContent := renderHTML(bundles, g)
	if err := os.WriteFile(filepath.Join(outDir, "report.html"), []byte(htmlContent), 0644); err != nil {
		return err
	}

	return nil
}

func renderDOT(g AttackGraph) string {
	var buf bytes.Buffer
	buf.WriteString("digraph ContextHunter_AttackGraph {\n")
	buf.WriteString("  rankdir=LR;\n")
	buf.WriteString("  node [shape=box, style=\"rounded,filled\", fontname=\"Consolas\", fontsize=10];\n")
	buf.WriteString("  edge [fontname=\"Consolas\", fontsize=9];\n\n")

	for _, n := range g.Nodes {
		fill := "#ECEFF1"
		switch n.Type {
		case "WAF_PROFILE":
			fill = "#FFF3E0"
		case "ENUMERATED_PRINCIPAL":
			fill = "#E3F2FD"
		case "API_ENDPOINT":
			fill = "#E8F5E9"
		case "TECH_FINGERPRINT":
			fill = "#F3E5F5"
		case "CONTEXTUAL_CVE":
			if n.Tier == "HIGH" {
				fill = "#FFEBEE"
			} else {
				fill = "#FFFDE7"
			}
		case "VALIDATED_POC":
			fill = "#FCE4EC"
		}
		fmt.Fprintf(&buf, "  %q [label=%q, fillcolor=%q];\n", n.ID, n.Label, fill)
	}
	buf.WriteString("\n")
	for _, e := range g.Edges {
		fmt.Fprintf(&buf, "  %q -> %q [label=\"%s (%.2f)\"];\n", e.Source, e.Target, e.Relation, e.Weight)
	}
	buf.WriteString("}\n")
	return buf.String()
}

func renderBountyMarkdown(bundles []TargetBundle) string {
	var buf bytes.Buffer
	buf.WriteString("# KINETIX — Contextual Bug Bounty Triage Report\n")
	buf.WriteString("> **Created by:** Oscar Emiliano Constanzo Quezada | **Notice:** Created exclusively for authorized targets.\n\n")
	for _, b := range bundles {
		fmt.Fprintf(&buf, "## Target Environment: `%s` (%s)\n\n", b.Name, b.Fingerprint.TargetURL)
		if b.WAF != nil {
			fmt.Fprintf(&buf, "- **WAF Profile:** Vendor=`%s`, Enforcement=`%s`, ParanoiaLevel=`%d`\n", b.WAF.Vendor, b.WAF.EnforcementMode, b.WAF.ParanoiaLevel)
		}
		if b.Enumeration != nil && len(b.Enumeration.ValidPrincipals) > 0 {
			for _, p := range b.Enumeration.ValidPrincipals {
				fmt.Fprintf(&buf, "- **Enumerated Identity:** `%s` via `%s` (Mean Latency: `%.2f ms` vs Baseline `%.2f ms`, Welch's `t = %.2f`, Confidence: `%.2f`)\n",
					p.Identifier, p.DiscoveryVector, p.MeanLatencyMs, p.BaselineMs, p.TStatistic, p.Confidence)
			}
		}
		buf.WriteString("\n### Contextual CVE Prioritization\n\n")
		buf.WriteString("| CVE ID | Tier | P_exec | Contextual Risk | V_match | W_pass | E_exp | A_viable | Diagnostic / Bottleneck |\n")
		buf.WriteString("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
		for _, f := range b.Findings {
			if f.FactorBreakdown["V_match"] == 0 && !strings.Contains(f.BottleneckReason, "Patched") {
				continue
			}
			fmt.Fprintf(&buf, "| **%s** | `%s` | `%.3f` | `%.1f/100` | `%.2f` | `%.2f` | `%.2f` | `%.2f` | %s |\n",
				f.CVEID, f.Tier, f.ProbabilityScore, f.ContextualRisk,
				f.FactorBreakdown["V_match"], f.FactorBreakdown["W_pass"],
				f.FactorBreakdown["E_exp"], f.FactorBreakdown["A_viable"],
				f.BottleneckReason)
		}
		buf.WriteString("\n")
		for _, f := range b.Findings {
			if ev, ok := b.Evidences[f.CVEID]; ok && ev != nil && ev.Validated {
				fmt.Fprintf(&buf, "#### Verified Non-Destructive PoC — `%s`\n", f.CVEID)
				fmt.Fprintf(&buf, "- **Request:** `%s`\n", ev.RequestLine)
				fmt.Fprintf(&buf, "- **HTTP Status:** `%d` (`%d bytes` read via bounded Range header)\n", ev.StatusCode, ev.BytesRead)
				fmt.Fprintf(&buf, "- **Cryptographic Seal (SHA-256):** `%s`\n", ev.EvidenceSHA256)
				fmt.Fprintf(&buf, "- **Reproduction Command:**\n```bash\n%s\n```\n", ev.ReproCurl)
				fmt.Fprintf(&buf, "- **Remediation:** %s\n\n", f.Remediation)
			}
		}
	}
	return buf.String()
}

func renderHTML(bundles []TargetBundle, g AttackGraph) string {
	var buf bytes.Buffer
	buf.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>ContextHunter (KINETIX) Report</title>
<style>
body { background:#0d1117; color:#c9d1d9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", monospace; margin: 2rem; }
h1, h2, h3 { color:#58a6ff; }
.card { background:#161b22; border:1px solid #30363d; border-radius:8px; padding:1.2rem; margin-bottom:1.5rem; }
table { width:100%; border-collapse:collapse; margin-top:0.8rem; }
th, td { border:1px solid #30363d; padding:0.6rem; text-align:left; font-size:0.9rem; }
th { background:#21262d; }
.HIGH { color:#ff7b72; font-weight:bold; }
.MEDIUM { color:#d29922; font-weight:bold; }
.LOW { color:#8b949e; }
code { background:#21262d; padding:2px 6px; border-radius:4px; color:#79c0ff; }
</style></head><body>
<h1>ContextHunter (KINETIX) — Contextual Attack Surface Dashboard</h1>`)

	for _, b := range bundles {
		fmt.Fprintf(&buf, `<div class="card"><h2>%s (<code>%s</code>)</h2>`, b.Name, b.Fingerprint.TargetURL)
		if b.WAF != nil {
			fmt.Fprintf(&buf, `<p><strong>WAF Profile:</strong> Vendor=<code>%s</code> | Mode=<code>%s</code> | Paranoia=<code>%d</code></p>`,
				b.WAF.Vendor, b.WAF.EnforcementMode, b.WAF.ParanoiaLevel)
		}
		buf.WriteString(`<table><thead><tr><th>CVE ID</th><th>Tier</th><th>P_exec</th><th>Risk</th><th>Diagnostic</th><th>PoC Status</th></tr></thead><tbody>`)
		for _, f := range b.Findings {
			if f.FactorBreakdown["V_match"] == 0 && !strings.Contains(f.BottleneckReason, "Patched") {
				continue
			}
			pocStatus := "Skipped (Tier < HIGH)"
			if ev, ok := b.Evidences[f.CVEID]; ok && ev != nil && ev.Validated {
				pocStatus = fmt.Sprintf("VERIFIED (SHA256: %s...)", ev.EvidenceSHA256[:12])
			}
			fmt.Fprintf(&buf, `<tr><td><code>%s</code></td><td class="%s">%s</td><td>%.3f</td><td>%.1f</td><td>%s</td><td><code>%s</code></td></tr>`,
				f.CVEID, f.Tier, f.Tier, f.ProbabilityScore, f.ContextualRisk, f.BottleneckReason, pocStatus)
		}
		buf.WriteString(`</tbody></table></div>`)
	}
	buf.WriteString(`</body></html>`)
	return buf.String()
}

func sanitizeID(s string) string {
	r := strings.NewReplacer("/", "_", ":", "_", ".", "_", "-", "_", "{", "", "}", "")
	return r.Replace(s)
}
