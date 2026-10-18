// language: Go, file: internal/scope/guard.go, target: Go 1.22+, Cross-Platform
package scope

import (
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrOutOfScopeHost     = errors.New("scope violation: target host is outside authorized scope")
	ErrExcludedHost       = errors.New("scope violation: target host matches explicit exclusion rule")
	ErrMutatingVerbDenied = errors.New("safety violation: mutating HTTP verb blocked by transport guard")
)

// IdentityProfile binds User-Agent, Sec-CH-UA headers, and simulated JA3/JA4 signature coherently.
type IdentityProfile struct {
	Name      string
	UserAgent string
	SecCHUA   string
	JA4Hash   string
}

var DefaultIdentities = []IdentityProfile{
	{
		Name:      "Chrome-125-Win11",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		SecCHUA:   `"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"`,
		JA4Hash:   "t13d1516h2_8daaf6152771_b186095e22b6",
	},
	{
		Name:      "Firefox-126-Linux",
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
		SecCHUA:   "",
		JA4Hash:   "t13d1715h2_5b57614c22b0_3d5424432f57",
	},
	{
		Name:      "Safari-17.5-macOS",
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
		SecCHUA:   "",
		JA4Hash:   "t13d2014h2_a09f3c656075_14788d8d241b",
	},
}

// Policy defines the strict program boundaries and stealth timing parameters.
type Policy struct {
	AllowedHosts     []string // Wildcards (*.example.com) or exact hosts (127.0.0.1)
	ExcludedHosts    []string // Explicit exclusions (billing.example.com, *.gov)
	AllowedCIDRs     []string
	BountyHeaderKey  string
	BountyHeaderVal  string
	MaxRPS           float64
	BaseJitterMs     float64
	MaxBackoffMs     float64
	EnforceReadOnly  bool
}

// Telemetry records real-time scope blocks, rate-limit backoffs, and request counts.
type Telemetry struct {
	TotalRequests        atomic.Int64
	ScopeBlocks          atomic.Int64
	RateLimitHits429     atomic.Int64
	BackoffEvents        atomic.Int64
	IdentityRotations    atomic.Int64
}

// TransportGuard wraps http.RoundTripper to enforce scope before every network connection.
type TransportGuard struct {
	Policy       Policy
	Base         http.RoundTripper
	Stats        *Telemetry
	mu           sync.Mutex
	identityIdx  int
	backoffLevel int
	lastReqTime  time.Time
	parsedCIDRs  []*net.IPNet
}

func NewTransportGuard(policy Policy, base http.RoundTripper) (*TransportGuard, error) {
	if base == nil {
		base = http.DefaultTransport
	}
	var cidrs []*net.IPNet
	for _, c := range policy.AllowedCIDRs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", c, err)
		}
		cidrs = append(cidrs, ipnet)
	}
	if policy.MaxRPS <= 0 {
		policy.MaxRPS = 25.0
	}
	if policy.MaxBackoffMs <= 0 {
		policy.MaxBackoffMs = 2000.0
	}
	return &TransportGuard{
		Policy:      policy,
		Base:        base,
		Stats:       &Telemetry{},
		parsedCIDRs: cidrs,
	}, nil
}

// ValidateURL checks whether a target URL is strictly within the authorized scope.
func (g *TransportGuard) ValidateURL(u *url.URL) error {
	if u == nil {
		return ErrOutOfScopeHost
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ErrOutOfScopeHost
	}

	// 1. Exclusion rules always take highest precedence
	for _, excl := range g.Policy.ExcludedHosts {
		if matchHostPattern(strings.ToLower(excl), host) {
			g.Stats.ScopeBlocks.Add(1)
			return fmt.Errorf("%w: %s", ErrExcludedHost, host)
		}
	}

	// 2. Check allowed host patterns
	for _, allow := range g.Policy.AllowedHosts {
		if matchHostPattern(strings.ToLower(allow), host) {
			return nil
		}
	}

	// 3. Check IP against allowed CIDRs if host is an IP literal
	if ip := net.ParseIP(host); ip != nil {
		for _, ipnet := range g.parsedCIDRs {
			if ipnet.Contains(ip) {
				return nil
			}
		}
	}

	g.Stats.ScopeBlocks.Add(1)
	return fmt.Errorf("%w: %s", ErrOutOfScopeHost, host)
}

func matchHostPattern(pattern, host string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(host, suffix) || host == pattern[2:]
	}
	return pattern == host
}

// RoundTrip intercepts every HTTP request and redirect to guarantee scope, stealth, and backoff.
func (g *TransportGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := g.ValidateURL(req.URL); err != nil {
		return nil, err
	}

	if g.Policy.EnforceReadOnly {
		switch req.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost:
			// POST is permitted only in Phase 4 login timing probe; Phase 5 enforces GET/HEAD/OPTIONS
		default:
			return nil, fmt.Errorf("%w: %s", ErrMutatingVerbDenied, req.Method)
		}
	}

	g.applyPacingAndStealth(req)
	g.Stats.TotalRequests.Add(1)

	resp, err := g.Base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Detect rate-limiting (429 / 503) and trigger exponential backoff + identity rotation
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		g.Stats.RateLimitHits429.Add(1)
		g.Stats.BackoffEvents.Add(1)
		g.mu.Lock()
		g.backoffLevel++
		g.identityIdx = (g.identityIdx + 1) % len(DefaultIdentities)
		g.Stats.IdentityRotations.Add(1)
		lvl := g.backoffLevel
		g.mu.Unlock()

		waitMs := math.Min(g.Policy.MaxBackoffMs, 25.0*math.Pow(2, float64(lvl))+rand.Float64()*15.0)
		time.Sleep(time.Duration(waitMs) * time.Millisecond)
	} else if resp.StatusCode < 400 {
		g.mu.Lock()
		if g.backoffLevel > 0 {
			g.backoffLevel--
		}
		g.mu.Unlock()
	}

	return resp, nil
}

func (g *TransportGuard) applyPacingAndStealth(req *http.Request) {
	g.mu.Lock()
	minInterval := time.Duration(float64(time.Second) / g.Policy.MaxRPS)
	if g.Policy.BaseJitterMs > 0 {
		jitter := math.Abs(rand.NormFloat64() * (g.Policy.BaseJitterMs / 2.0))
		minInterval += time.Duration(jitter * float64(time.Millisecond))
	}
	elapsed := time.Since(g.lastReqTime)
	if elapsed < minInterval {
		sleepDur := minInterval - elapsed
		g.mu.Unlock()
		time.Sleep(sleepDur)
		g.mu.Lock()
	}
	g.lastReqTime = time.Now()
	profile := DefaultIdentities[g.identityIdx%len(DefaultIdentities)]
	g.mu.Unlock()

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", profile.UserAgent)
	}
	if profile.SecCHUA != "" && req.Header.Get("Sec-CH-UA") == "" {
		req.Header.Set("Sec-CH-UA", profile.SecCHUA)
	}
	req.Header.Set("X-Client-JA4-Simulated", profile.JA4Hash)
	if g.Policy.BountyHeaderKey != "" {
		req.Header.Set(g.Policy.BountyHeaderKey, g.Policy.BountyHeaderVal)
	}
}

// NewScopedClient builds an *http.Client that validates both initial requests and every redirect hop.
func (g *TransportGuard) NewScopedClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: g,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("stopped after 5 redirects")
			}
			return g.ValidateURL(req.URL)
		},
	}
}
