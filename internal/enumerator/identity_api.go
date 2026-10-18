// language: Go, file: internal/enumerator/identity_api.go, target: Go 1.22+, Cross-Platform
package enumerator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

type Principal struct {
	Identifier      string  `json:"identifier"`
	DiscoveryVector string  `json:"discovery_vector"` // timing_oracle_welch_t, status_differential
	MeanLatencyMs   float64 `json:"mean_latency_ms"`
	BaselineMs      float64 `json:"baseline_ms"`
	TStatistic      float64 `json:"t_statistic"`
	Confidence      float64 `json:"confidence"`
}

type EndpointBinding struct {
	PrincipalID string  `json:"principal_id"`
	Endpoint    string  `json:"endpoint"`
	StatusCode  int     `json:"status_code"`
	Relation    string  `json:"relation"`
	Confidence  float64 `json:"confidence"`
}

type EnumerationResult struct {
	ExposedEndpoints map[string]int    `json:"exposed_endpoints"` // Path -> HTTP Status
	ValidPrincipals  []Principal       `json:"valid_principals"`
	Bindings         []EndpointBinding `json:"bindings"`
	MaxPrincipalConf float64           `json:"max_principal_conf"`
}

type Enumerator struct {
	Client *http.Client
}

func NewEnumerator(client *http.Client) *Enumerator {
	return &Enumerator{Client: client}
}

var defaultCandidateEndpoints = []string{
	"/rest/products/search",
	"/api/Users",
	"/rest/admin/application-configuration",
	"/workshop/api/mechanic/receive_report",
	"/identity/api/v2/user/dashboard",
	"/webtools/control/main",
	"/api/v2/reports/export",
	"/vulnerabilities/sqli/",
}

var defaultCandidatePrincipals = []string{
	"svc_mechanic@crapi.local",
	"svc_reporting@target.example",
	"invalid_candidate_01@crapi.local",
}

// Run executes API surface verification, differential identity timing analysis, and BOLA binding.
func (e *Enumerator) Run(
	ctx context.Context,
	baseURL string,
	jsRoutes []string,
	soft404Hash string,
) (*EnumerationResult, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	res := &EnumerationResult{
		ExposedEndpoints: make(map[string]int),
	}

	// 1. Consolidate candidate routes from JS AST + standard API dictionary
	routeMap := make(map[string]struct{})
	for _, r := range defaultCandidateEndpoints {
		routeMap[r] = struct{}{}
	}
	for _, r := range jsRoutes {
		routeMap[r] = struct{}{}
	}

	for route := range routeMap {
		status, bodyHash, err := e.probeEndpoint(ctx, baseURL+route)
		if err != nil {
			continue
		}
		if soft404Hash != "" && bodyHash == soft404Hash {
			// Discard SPA catch-all soft-404s
			res.ExposedEndpoints[route] = http.StatusNotFound
			continue
		}
		res.ExposedEndpoints[route] = status
	}

	// 2. Differential Timing Oracle (Welch's t-test) if login endpoint exists
	for _, authPath := range []string{"/identity/api/auth/login", "/api/general/login/sesion-valida"} {
		loginStatus, _, err := e.probeEndpoint(ctx, baseURL+authPath)
		if err == nil && loginStatus != http.StatusNotFound {
			res.ExposedEndpoints[authPath] = loginStatus
			e.evaluateTimingOracle(ctx, baseURL+authPath, res)
		}
	}

	// 3. Correlate discovered principals with exposed API endpoints
	for _, p := range res.ValidPrincipals {
		if p.Confidence > res.MaxPrincipalConf {
			res.MaxPrincipalConf = p.Confidence
		}
		for ep, st := range res.ExposedEndpoints {
			if st == http.StatusOK || st == http.StatusUnauthorized || st == http.StatusMethodNotAllowed {
				if strings.Contains(ep, "mechanic") || strings.Contains(ep, "user") || strings.Contains(ep, "reports") {
					res.Bindings = append(res.Bindings, EndpointBinding{
						PrincipalID: p.Identifier,
						Endpoint:    ep,
						StatusCode:  st,
						Relation:    "CANDIDATE_BOLA_OR_AUTH_SURFACE",
						Confidence:  math.Round(p.Confidence*0.95*100) / 100,
					})
				}
			}
		}
	}

	return res, nil
}

func (e *Enumerator) probeEndpoint(ctx context.Context, fullURL string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := e.Client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	sum := sha256.Sum256(body)
	return resp.StatusCode, hex.EncodeToString(sum[:]), nil
}

func (e *Enumerator) evaluateTimingOracle(ctx context.Context, loginURL string, res *EnumerationResult) {
	const samples = 7
	baselineIdent := "ctx_nonexistent_baseline_99812@invalid.local"

	for _, candidate := range defaultCandidatePrincipals {
		var baseLatencies []float64
		var candLatencies []float64

		// Interleaved sampling over persistent keep-alive connection to neutralize network drift
		for i := 0; i < samples; i++ {
			bMs, err1 := e.measureAuthCheck(ctx, loginURL, baselineIdent)
			cMs, err2 := e.measureAuthCheck(ctx, loginURL, candidate)
			if err1 == nil && err2 == nil {
				baseLatencies = append(baseLatencies, bMs)
				candLatencies = append(candLatencies, cMs)
			}
		}

		if len(baseLatencies) < 5 {
			continue
		}

		meanBase, varBase := meanAndVariance(baseLatencies)
		meanCand, varCand := meanAndVariance(candLatencies)
		delta := meanCand - meanBase

		// Welch's t-statistic: t = (meanCand - meanBase) / sqrt(varCand/N + varBase/N)
		denom := math.Sqrt((varCand / float64(len(candLatencies))) + (varBase / float64(len(baseLatencies))) + 0.001)
		tStat := delta / denom

		// For df >= 6, t > 3.707 corresponds to one-tailed p < 0.005; require delta >= 15ms
		if tStat >= 3.70 && delta >= 15.0 {
			conf := math.Min(0.96, 0.75+(tStat/40.0))
			res.ValidPrincipals = append(res.ValidPrincipals, Principal{
				Identifier:      candidate,
				DiscoveryVector: "timing_oracle_welch_t",
				MeanLatencyMs:   math.Round(meanCand*100) / 100,
				BaselineMs:      math.Round(meanBase*100) / 100,
				TStatistic:      math.Round(tStat*100) / 100,
				Confidence:      math.Round(conf*100) / 100,
			})
		}
	}
}

func (e *Enumerator) measureAuthCheck(ctx context.Context, loginURL, email string) (float64, error) {
	payload := fmt.Sprintf(`{"email":%q,"password":"ctx_probe_fixed_len_check"}`, email)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewBufferString(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := e.Client.Do(req)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	elapsedMs := float64(time.Since(start).Microseconds()) / 1000.0
	return elapsedMs, nil
}

func meanAndVariance(vals []float64) (float64, float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	mean := sum / float64(len(vals))
	if len(vals) == 1 {
		return mean, 0
	}
	varSum := 0.0
	for _, v := range vals {
		diff := v - mean
		varSum += diff * diff
	}
	return mean, varSum / float64(len(vals)-1)
}
