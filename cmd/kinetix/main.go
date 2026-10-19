package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Underh0st/kinetix-contexthunter/internal/correlator"
	"github.com/Underh0st/kinetix-contexthunter/internal/enumerator"
	"github.com/Underh0st/kinetix-contexthunter/internal/fingerprint"
	"github.com/Underh0st/kinetix-contexthunter/internal/graph"
	"github.com/Underh0st/kinetix-contexthunter/internal/scope"
	"github.com/Underh0st/kinetix-contexthunter/internal/store"
	"github.com/Underh0st/kinetix-contexthunter/internal/ui"
	"github.com/Underh0st/kinetix-contexthunter/internal/validator"
	"github.com/Underh0st/kinetix-contexthunter/internal/waf"
	"github.com/Underh0st/kinetix-contexthunter/pkg/testbench"
)

const (
	bountyHeaderKey = "X-Bug-Bounty"
	bountyHeaderVal = "KINETIX-ContextHunter-Verifier"
	clientTimeout   = 10 * time.Second
)

func main() {
	var (
		targetLong   = flag.String("target", "", "Target domain or URL (e.g., target.com or https://api.target.com).")
		targetShort  = flag.String("t", "", "Target domain or URL (shorthand for --target).")
		allowedHosts = flag.String("allowed-hosts", "", "Comma-separated in-scope host patterns (e.g., *.target.com,target.com).")
		enablePoC    = flag.Bool("enable-poc", false, "Authorize Phase 5 zero-mutation PoC verification (GET/HEAD/OPTIONS, max 256 bytes).")
		maxRPS       = flag.Float64("max-rps", 15.0, "Maximum requests per second per host before Gaussian jitter is added.")
		outDir       = flag.String("out-dir", "./artifacts", "Output directory for attack_graph.json, attack_graph.dot, bounty_report.md and report.html.")
		benchmark    = flag.Bool("benchmark", false, "Launch the internal 6-environment QA benchmark and validation suite.")
		demoTarget   = flag.Bool("demo-target", false, "Launch a local simulated target and execute a full single-target scan.")
		noColor      = flag.Bool("no-color", false, "Disable ANSI colors for plain-text log pipelines.")
	)
	flag.Parse()

	console := ui.NewConsole(*noColor)
	console.PrintBanner()

	ctx := context.Background()

	if *benchmark {
		if err := runBenchmark(ctx, console, *outDir); err != nil {
			fail(err)
		}
		return
	}

	if *demoTarget {
		if err := runDemoTarget(ctx, console, *enablePoC, *maxRPS, *outDir); err != nil {
			fail(err)
		}
		return
	}

	target := strings.TrimSpace(*targetLong)
	if target == "" {
		target = strings.TrimSpace(*targetShort)
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "error: a target is required (-t <target>), or use --benchmark / --demo-target")
		flag.Usage()
		os.Exit(2)
	}

	normalized, host, err := normalizeTarget(target)
	if err != nil {
		fail(err)
	}

	hosts := parseAllowedHosts(*allowedHosts)
	if len(hosts) == 0 {
		hosts = defaultScope(host)
	}

	policy := scope.Policy{
		AllowedHosts:    hosts,
		BountyHeaderKey: bountyHeaderKey,
		BountyHeaderVal: bountyHeaderVal,
		MaxRPS:          *maxRPS,
		BaseJitterMs:    1.0,
		MaxBackoffMs:    120.0,
		EnforceReadOnly: true,
	}

	if err := runScan(ctx, console, policy, normalized, host, *enablePoC, *outDir); err != nil {
		fail(err)
	}
}

func runScan(ctx context.Context, console *ui.Console, policy scope.Policy, targetURL, name string, enablePoC bool, outDir string) error {
	guard, err := scope.NewTransportGuard(policy, http.DefaultTransport)
	if err != nil {
		return err
	}
	client := guard.NewScopedClient(clientTimeout)

	console.PrintScopeConfig(targetURL, policy)

	console.PrintSection("1", "Multidimensional Fingerprinting")
	fpRes, err := fingerprint.NewScanner(client).Scan(ctx, targetURL)
	if err != nil {
		return fmt.Errorf("fingerprint phase failed: %w", err)
	}
	console.PrintFingerprint(fpRes)

	console.PrintSection("2", "Benign Syntactic WAF Profiling")
	wafProf, err := waf.NewProfiler(client).Characterize(ctx, targetURL)
	if err != nil {
		return fmt.Errorf("waf phase failed: %w", err)
	}
	console.PrintWAF(wafProf)

	console.PrintSection("4", "API Binding & Differential Identity Oracle")
	enumRes, err := enumerator.NewEnumerator(client).Run(ctx, targetURL, fpRes.DiscoveredRoutes, fpRes.Soft404Hash)
	if err != nil {
		return fmt.Errorf("enumeration phase failed: %w", err)
	}
	console.PrintEnumeration(enumRes)

	console.PrintSection("3", "Contextual CVE Correlation")
	tCtx := correlator.TargetContext{
		TargetURL:        targetURL,
		DetectedCPEs:     fpRes.CombinedCPEs,
		ExposedEndpoints: enumRes.ExposedEndpoints,
		WAF:              wafProf,
		MaxUserEnumConf:  enumRes.MaxPrincipalConf,
	}
	findings := correlator.EvaluateAll(correlator.DefaultCatalog(), tCtx)

	evidences := make(map[string]*validator.Evidence)
	if enablePoC {
		console.PrintSection("5", "Zero-Mutation PoC Validation")
		poc := validator.NewValidator(client, true, policy.BountyHeaderVal)
		for _, f := range findings {
			if f.Tier != "HIGH" {
				continue
			}
			ev, verr := poc.ValidateFinding(ctx, f)
			if verr == nil && ev != nil && ev.Validated {
				evidences[f.CVEID] = ev
			}
		}
	}
	console.PrintFindings(findings, evidences)

	localStore := store.NewLocalStore()
	localStore.RecordTarget(name, targetURL, wafProf.Vendor, fpRes.CombinedCPEs)

	console.PrintSection("6", "Attack Graph Export")
	bundles := []graph.TargetBundle{{
		Name:        name,
		Fingerprint: fpRes,
		WAF:         wafProf,
		Enumeration: enumRes,
		Findings:    findings,
		Evidences:   evidences,
	}}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := graph.ExportAll(outDir, bundles, graph.BuildGraph(bundles)); err != nil {
		return fmt.Errorf("graph export failed: %w", err)
	}
	if err := localStore.Flush(outDir); err != nil {
		return fmt.Errorf("cache flush failed: %w", err)
	}

	fmt.Printf("\nArtifacts written to %s\n", outDir)
	return nil
}

func runBenchmark(ctx context.Context, console *ui.Console, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	summary, err := testbench.RunFullBenchmark(ctx, outDir)
	if err != nil {
		return err
	}
	console.PrintBenchmarkSummary(summary, outDir)
	return nil
}

func runDemoTarget(ctx context.Context, console *ui.Console, enablePoC bool, maxRPS float64, outDir string) error {
	envs := testbench.SpinUpEnvironments()
	defer func() {
		for _, e := range envs {
			e.Server.Close()
		}
	}()
	if len(envs) == 0 {
		return fmt.Errorf("no simulated environment available")
	}

	env := envs[0]
	policy := scope.Policy{
		AllowedHosts:    []string{"127.0.0.1", "localhost"},
		AllowedCIDRs:    []string{"127.0.0.0/8"},
		BountyHeaderKey: bountyHeaderKey,
		BountyHeaderVal: bountyHeaderVal,
		MaxRPS:          maxRPS,
		BaseJitterMs:    1.0,
		MaxBackoffMs:    120.0,
		EnforceReadOnly: true,
	}
	return runScan(ctx, console, policy, env.Server.URL, env.Name, enablePoC, outDir)
}

func normalizeTarget(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		scheme := "https"
		lower := strings.ToLower(raw)
		if strings.HasPrefix(lower, "localhost") || strings.HasPrefix(lower, "127.0.0.1") {
			scheme = "http"
		}
		raw = scheme + "://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("invalid target %q: %w", raw, err)
	}
	if u.Hostname() == "" {
		return "", "", fmt.Errorf("invalid target %q: empty host", raw)
	}
	return strings.TrimRight(u.String(), "/"), u.Hostname(), nil
}

func parseAllowedHosts(csv string) []string {
	var out []string
	for _, part := range strings.Split(csv, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func defaultScope(host string) []string {
	hosts := []string{host}
	if !strings.HasPrefix(host, "*.") && strings.Contains(host, ".") {
		hosts = append(hosts, "*."+host)
	}
	return hosts
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
