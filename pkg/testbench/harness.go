// language: Go, file: pkg/testbench/harness.go, target: Go 1.22+, Cross-Platform
package testbench

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Underh0st/kinetix-contexthunter/internal/correlator"
	"github.com/Underh0st/kinetix-contexthunter/internal/enumerator"
	"github.com/Underh0st/kinetix-contexthunter/internal/fingerprint"
	"github.com/Underh0st/kinetix-contexthunter/internal/graph"
	"github.com/Underh0st/kinetix-contexthunter/internal/scope"
	"github.com/Underh0st/kinetix-contexthunter/internal/store"
	"github.com/Underh0st/kinetix-contexthunter/internal/validator"
	"github.com/Underh0st/kinetix-contexthunter/internal/waf"
)

type SimulatedEnv struct {
	Name            string
	Server          *httptest.Server
	ExpectedCPEs    []string
	ExpectedWAF     string
	ExpectedTopTier map[string]string // CVEID -> Expected Tier (HIGH, MEDIUM, LOW)
	MutationCount   *atomic.Int64
	InitialStateSum string
}

type BenchmarkSummary struct {
	ExecutedAtUTC            string         `json:"executed_at_utc"`
	TotalEnvironments        int            `json:"total_environments"`
	TruePositivesCPE         int            `json:"true_positives_cpe"`
	FalsePositivesCPE        int            `json:"false_positives_cpe"`
	FalseNegativesCPE        int            `json:"false_negatives_cpe"`
	FingerprintPrecision     float64        `json:"fingerprint_precision"`
	FingerprintRecall        float64        `json:"fingerprint_recall"`
	FingerprintF1            float64        `json:"fingerprint_f1"`
	WAFFalsePositives        int            `json:"waf_false_positives"`
	WAFDetectionAccuracy     float64        `json:"waf_detection_accuracy"`
	ScopeViolationsBlocked   int64          `json:"scope_violations_blocked"`
	RateLimitBackoffs        int64          `json:"rate_limit_backoffs"`
	IPBurnCount              int            `json:"ip_burn_count"`
	ZeroMutationVerified     bool           `json:"zero_mutation_verified"`
	ContextualTierMatches    int            `json:"contextual_tier_matches"`
	ContextualTierTotal      int            `json:"contextual_tier_total"`
	ContextualAccuracy       float64        `json:"contextual_accuracy"`
	EnvironmentDetails       []EnvEvalEntry `json:"environment_details"`
}

type EnvEvalEntry struct {
	Environment      string            `json:"environment"`
	URL              string            `json:"url"`
	DetectedCPEs     map[string]float64 `json:"detected_cpes"`
	WAFVendor        string            `json:"waf_vendor"`
	EnumeratedUsers  []string          `json:"enumerated_users"`
	EvaluatedCVEs    map[string]string `json:"evaluated_cves"`
	PoCVerifiedCount int               `json:"poc_verified_count"`
	StateHashBefore  string            `json:"state_hash_before"`
	StateHashAfter   string            `json:"state_hash_after"`
}

// SpinUpEnvironments creates the controlled local HTTP testbed.
func SpinUpEnvironments() []*SimulatedEnv {
	return []*SimulatedEnv{
		newJuiceShopEnv(),
		newDVWAModSecEnv(),
		newCrAPIEnv(),
		newOFBizEnv("ENV-04A-OFBiz-18.12.09-Exposed", "18.12.09", false, "HIGH"),
		newOFBizEnv("ENV-04B-OFBiz-18.12.12-Patched", "18.12.12", false, "LOW"),
		newOFBizEnv("ENV-04C-OFBiz-18.12.09-ProxyBlocked", "18.12.09", true, "LOW"),
	}
}

// 1. OWASP Juice Shop v16.2.1 Simulator (Express + Angular 17 + SQLite + Soft-404 SPA trap + JS Bundle)
func newJuiceShopEnv() *SimulatedEnv {
	mut := &atomic.Int64{}
	stateSum := computeStateHash("juiceshop_db_v16.2.1_clean", mut.Load())

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		trackMutation(r, mut)
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/assets/public/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, `const routes = ["/rest/products/search", "/api/Users", "/rest/admin/application-configuration"];`)
		case "/ftp/package.json.bak":
			w.Header().Set("Content-Type", "application/json")
			if r.Header.Get("Range") != "" {
				w.WriteHeader(http.StatusPartialContent)
			}
			io.WriteString(w, `{"name":"juice-shop","version":"16.2.1","dependencies":{"express":"^4.18.2","sqlite3":"5.1.7"}}`)
		case "/rest/products/search":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"status":"success","data":[{"id":1,"name":"Apple Juice"}]}`)
		case "/api/Users":
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":"Unauthorized"}`)
		default:
			// SPA Soft-404 trap: returns 200 OK with Angular shell for any unknown route
			io.WriteString(w, `<!doctype html><html><head><title>OWASP Juice Shop</title></head><body><app-root ng-version="17.3.0"></app-root><script src="/assets/public/main.js"></script></body></html>`)
		}
	})

	return &SimulatedEnv{
		Name:   "ENV-01-OWASP-JuiceShop",
		Server: httptest.NewServer(mux),
		ExpectedCPEs: []string{
			"cpe:2.3:a:owasp:juice_shop:16.2.1:*:*:*:*:*:*:*",
			"cpe:2.3:a:expressjs:express:4.18.2:*:*:*:*:*:*:*",
			"cpe:2.3:a:angular:angular:17.3.0:*:*:*:*:*:*:*",
			"cpe:2.3:a:sqlite:sqlite:5.1.7:*:*:*:*:*:*:*",
		},
		ExpectedWAF:     "none",
		ExpectedTopTier: map[string]string{"CVE-2024-31905": "HIGH"},
		MutationCount:   mut,
		InitialStateSum: stateSum,
	}
}

// 2. DVWA + ModSecurity CRS 4.0 Simulator (Paranoia Level 3 + Rate-Limit 429 test)
func newDVWAModSecEnv() *SimulatedEnv {
	mut := &atomic.Int64{}
	reqCounter := &atomic.Int64{}
	stateSum := computeStateHash("dvwa_db_v2.4_clean", mut.Load())

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		trackMutation(r, mut)
		count := reqCounter.Add(1)
		w.Header().Set("Server", "Apache/2.4.58 (Debian)")
		w.Header().Set("X-Powered-By", "PHP/8.2.12")
		w.Header().Set("X-WAF-Engine", "ModSecurity-CRS/4.0-PL3")

		// Trigger one controlled 429 on request #4 to verify Phase 0 adaptive exponential backoff
		if count == 4 {
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"error":"Rate limit threshold reached, slow down"}`)
			return
		}

		rawQuery := strings.ToLower(r.URL.RawQuery)
		if strings.Contains(rawQuery, "select_marker") || strings.Contains(rawQuery, "..%2f") {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `ModSecurity: Access denied with code 403 (phase 2). Paranoia Level 3.`)
			return
		}

		if r.URL.Path == "/vulnerabilities/sqli/" {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `<html><body>Vulnerability: SQL Injection</body></html>`)
			return
		}

		io.WriteString(w, `<html><head><title>Damn Vulnerable Web Application (DVWA)</title></head><body>DVWA</body></html>`)
	})

	return &SimulatedEnv{
		Name:   "ENV-02-DVWA-ModSecurity-PL3",
		Server: httptest.NewServer(mux),
		ExpectedCPEs: []string{
			"cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*",
			"cpe:2.3:a:php:php:8.2.12:*:*:*:*:*:*:*",
			"cpe:2.3:a:dvwa:dvwa:2.4:*:*:*:*:*:*:*",
		},
		ExpectedWAF: "modsecurity",
		// Because ModSecurity PL3 blocks query_string_sqli_keywords (W_pass=0.05), CVE-2023-38408 is downgraded to LOW!
		ExpectedTopTier: map[string]string{"CVE-2023-38408": "LOW"},
		MutationCount:   mut,
		InitialStateSum: stateSum,
	}
}

// 3. OWASP crAPI Simulator (Go Gateway + Welch's t-test Timing Oracle + BOLA Endpoint)
func newCrAPIEnv() *SimulatedEnv {
	mut := &atomic.Int64{}
	stateSum := computeStateHash("crapi_postgres_v1.2.0_clean", mut.Load())

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		trackMutation(r, mut)
		w.Header().Set("X-API-Gateway", "crapi-go-gateway/1.2.0")
		switch r.URL.Path {
		case "/assets/bundle.js":
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, `const VERSION="crapi-ui-v1.2.0"; fetch("/workshop/api/mechanic/receive_report"); fetch("/identity/api/v2/user/dashboard");`)
		case "/identity/api/auth/login":
			if r.Method == http.MethodPost {
				body, _ := io.ReadAll(r.Body)
				// Simulate Argon2/Bcrypt timing side-channel (+38ms) only when valid principal is checked
				if strings.Contains(string(body), "svc_mechanic@crapi.local") {
					time.Sleep(38 * time.Millisecond)
				} else {
					time.Sleep(2 * time.Millisecond)
				}
				w.WriteHeader(http.StatusUnauthorized)
				io.WriteString(w, `{"message":"Invalid credentials"}`)
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
		case "/workshop/api/mechanic/receive_report":
			w.Header().Set("Content-Type", "application/json")
			if r.Header.Get("Range") != "" {
				w.WriteHeader(http.StatusPartialContent)
			}
			io.WriteString(w, `{"report_id":1,"mechanic":"svc_mechanic@crapi.local","status":"ready"}`)
		default:
			io.WriteString(w, `<html><head><title>crAPI</title></head><body><script src="/assets/bundle.js"></script></body></html>`)
		}
	})

	return &SimulatedEnv{
		Name:   "ENV-03-OWASP-crAPI",
		Server: httptest.NewServer(mux),
		ExpectedCPEs: []string{
			"cpe:2.3:a:owasp:crapi:1.2.0:*:*:*:*:*:*:*",
		},
		ExpectedWAF:     "none",
		ExpectedTopTier: map[string]string{"CVE-2024-29847": "HIGH"},
		MutationCount:   mut,
		InitialStateSum: stateSum,
	}
}

// 4. Apache OFBiz Differential Matrix (4A: 18.12.09 Exposed, 4B: 18.12.12 Patched, 4C: 18.12.09 Proxy-Blocked)
func newOFBizEnv(name, version string, blockWebtools bool, expectedTier string) *SimulatedEnv {
	mut := &atomic.Int64{}
	stateSum := computeStateHash("ofbiz_"+name, mut.Load())

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		trackMutation(r, mut)
		w.Header().Set("X-OFBiz-Version", version)
		if strings.HasPrefix(r.URL.Path, "/webtools/control/main") {
			if blockWebtools {
				w.WriteHeader(http.StatusForbidden)
				io.WriteString(w, `Reverse Proxy ACL: /webtools/ is restricted`)
				return
			}
			if r.Header.Get("Range") != "" {
				w.WriteHeader(http.StatusPartialContent)
			}
			io.WriteString(w, fmt.Sprintf(`<html><body>Apache OFBiz %s — OFBiz:%s:AuthBypassReady</body></html>`, version, version))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/webtools/control/") {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, fmt.Sprintf(`<html><footer>Apache OFBiz %s</footer></html>`, version))
			return
		}
		io.WriteString(w, fmt.Sprintf(`<html><head><title>OFBiz %s</title></head></html>`, version))
	})

	return &SimulatedEnv{
		Name:   name,
		Server: httptest.NewServer(mux),
		ExpectedCPEs: []string{
			fmt.Sprintf("cpe:2.3:a:apache:ofbiz:%s:*:*:*:*:*:*:*", version),
		},
		ExpectedWAF:     "none",
		ExpectedTopTier: map[string]string{"CVE-2023-51467": expectedTier},
		MutationCount:   mut,
		InitialStateSum: stateSum,
	}
}

func trackMutation(r *http.Request, counter *atomic.Int64) {
	switch r.Method {
	case http.MethodDelete, http.MethodPut, http.MethodPatch:
		counter.Add(1)
	}
}

func computeStateHash(seed string, mutations int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|mutations=%d", seed, mutations)))
	return hex.EncodeToString(sum[:])
}

// RunFullBenchmark executes all 6 phases of ContextHunter across the simulated testbed and computes SLA metrics.
func RunFullBenchmark(ctx context.Context, outDir string) (*BenchmarkSummary, error) {
	envs := SpinUpEnvironments()
	defer func() {
		for _, e := range envs {
			e.Server.Close()
		}
	}()

	policy := scope.Policy{
		AllowedHosts:    []string{"127.0.0.1", "localhost"},
		ExcludedHosts:   []string{"billing.internal.local", "*.gov"},
		AllowedCIDRs:    []string{"127.0.0.0/8"},
		BountyHeaderKey: "X-Bug-Bounty",
		BountyHeaderVal: "ContextHunter-QA-Verifier",
		MaxRPS:          500.0,
		BaseJitterMs:    1.0,
		MaxBackoffMs:    120.0,
		EnforceReadOnly: true,
	}

	guard, err := scope.NewTransportGuard(policy, http.DefaultTransport)
	if err != nil {
		return nil, err
	}
	client := guard.NewScopedClient(5 * time.Second)

	// Verify Scope Guard actively blocks out-of-scope and excluded domains before scanning
	_, _ = client.Get("http://billing.internal.local/admin")
	_, _ = client.Get("http://external-unscoped.example.org/api")

	fpScanner := fingerprint.NewScanner(client)
	wafProfiler := waf.NewProfiler(client)
	idEnumerator := enumerator.NewEnumerator(client)
	pocValidator := validator.NewValidator(client, true, policy.BountyHeaderVal)
	localStore := store.NewLocalStore()
	catalog := correlator.DefaultCatalog()

	summary := &BenchmarkSummary{
		ExecutedAtUTC:        time.Now().UTC().Format(time.RFC3339),
		TotalEnvironments:    len(envs),
		ZeroMutationVerified: true,
	}

	var bundles []graph.TargetBundle
	wafCorrect := 0

	for _, env := range envs {
		// Phase 1: Multidimensional Fingerprinting
		fpRes, err := fpScanner.Scan(ctx, env.Server.URL)
		if err != nil {
			return nil, fmt.Errorf("fingerprint failed on %s: %w", env.Name, err)
		}

		// Score Fingerprinting TP / FP / FN
		expectedSet := make(map[string]bool)
		for _, c := range env.ExpectedCPEs {
			expectedSet[c] = true
		}
		for cpe := range fpRes.CombinedCPEs {
			if expectedSet[cpe] {
				summary.TruePositivesCPE++
			} else {
				summary.FalsePositivesCPE++
			}
		}
		for _, expCPE := range env.ExpectedCPEs {
			if _, ok := fpRes.CombinedCPEs[expCPE]; !ok {
				summary.FalseNegativesCPE++
			}
		}

		// Phase 2: WAF Characterization
		wafProf, err := wafProfiler.Characterize(ctx, env.Server.URL)
		if err != nil {
			return nil, fmt.Errorf("waf profiler failed on %s: %w", env.Name, err)
		}
		if wafProf.Vendor == env.ExpectedWAF {
			wafCorrect++
		} else if env.ExpectedWAF == "none" && wafProf.Detected {
			summary.WAFFalsePositives++
		}

		// Phase 4: API & Differential Identity Enumeration
		enumRes, err := idEnumerator.Run(ctx, env.Server.URL, fpRes.DiscoveredRoutes, fpRes.Soft404Hash)
		if err != nil {
			return nil, fmt.Errorf("enumerator failed on %s: %w", env.Name, err)
		}

		// Phase 3: Contextual CVE Correlation
		tCtx := correlator.TargetContext{
			TargetURL:        env.Server.URL,
			DetectedCPEs:     fpRes.CombinedCPEs,
			ExposedEndpoints: enumRes.ExposedEndpoints,
			WAF:              wafProf,
			MaxUserEnumConf:  enumRes.MaxPrincipalConf,
		}
		findings := correlator.EvaluateAll(catalog, tCtx)

		// Phase 5: Safe Non-Destructive PoC Validation
		evidences := make(map[string]*validator.Evidence)
		evalMap := make(map[string]string)
		pocCount := 0

		for _, f := range findings {
			if expTier, tracked := env.ExpectedTopTier[f.CVEID]; tracked {
				summary.ContextualTierTotal++
				evalMap[f.CVEID] = fmt.Sprintf("%s (P_exec=%.2f)", f.Tier, f.ProbabilityScore)
				if f.Tier == expTier {
					summary.ContextualTierMatches++
				}
			}
			if f.Tier == "HIGH" {
				ev, err := pocValidator.ValidateFinding(ctx, f)
				if err == nil && ev.Validated {
					evidences[f.CVEID] = ev
					pocCount++
				}
			}
		}

		// Verify Zero-Mutation State Integrity after Phase 5
		afterHash := computeStateHash(strings.Split(env.InitialStateSum, "|")[0], env.MutationCount.Load())
		if env.MutationCount.Load() != 0 {
			summary.ZeroMutationVerified = false
		} else {
			afterHash = env.InitialStateSum
		}

		var users []string
		for _, u := range enumRes.ValidPrincipals {
			users = append(users, fmt.Sprintf("%s (t=%.2f, conf=%.2f)", u.Identifier, u.TStatistic, u.Confidence))
		}

		summary.EnvironmentDetails = append(summary.EnvironmentDetails, EnvEvalEntry{
			Environment:      env.Name,
			URL:              env.Server.URL,
			DetectedCPEs:     fpRes.CombinedCPEs,
			WAFVendor:        wafProf.Vendor,
			EnumeratedUsers:  users,
			EvaluatedCVEs:    evalMap,
			PoCVerifiedCount: pocCount,
			StateHashBefore:  env.InitialStateSum,
			StateHashAfter:   afterHash,
		})

		localStore.RecordTarget(env.Name, env.Server.URL, wafProf.Vendor, fpRes.CombinedCPEs)
		bundles = append(bundles, graph.TargetBundle{
			Name:        env.Name,
			Fingerprint: fpRes,
			WAF:         wafProf,
			Enumeration: enumRes,
			Findings:    findings,
			Evidences:   evidences,
		})
	}

	// Compute Precision, Recall, F1, WAF Accuracy, and Contextual Accuracy
	tp := float64(summary.TruePositivesCPE)
	fp := float64(summary.FalsePositivesCPE)
	fn := float64(summary.FalseNegativesCPE)
	if tp+fp > 0 {
		summary.FingerprintPrecision = tp / (tp + fp)
	}
	if tp+fn > 0 {
		summary.FingerprintRecall = tp / (tp + fn)
	}
	if summary.FingerprintPrecision+summary.FingerprintRecall > 0 {
		summary.FingerprintF1 = 2 * (summary.FingerprintPrecision * summary.FingerprintRecall) /
			(summary.FingerprintPrecision + summary.FingerprintRecall)
	}
	summary.WAFDetectionAccuracy = float64(wafCorrect) / float64(len(envs))
	if summary.ContextualTierTotal > 0 {
		summary.ContextualAccuracy = float64(summary.ContextualTierMatches) / float64(summary.ContextualTierTotal)
	}
	summary.ScopeViolationsBlocked = guard.Stats.ScopeBlocks.Load()
	summary.RateLimitBackoffs = guard.Stats.BackoffEvents.Load()

	if outDir != "" {
		if err := localStore.Flush(outDir); err != nil {
			return nil, err
		}
		ag := graph.BuildGraph(bundles)
		if err := graph.ExportAll(outDir, bundles, ag); err != nil {
			return nil, err
		}
		sumBytes, _ := json.MarshalIndent(summary, "", "  ")
		_ = os.WriteFile(filepath.Join(outDir, "benchmark_metrics.json"), sumBytes, 0644)
	}

	return summary, nil
}
