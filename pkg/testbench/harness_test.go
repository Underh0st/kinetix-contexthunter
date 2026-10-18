// language: Go, file: pkg/testbench/harness_test.go, target: Go 1.22+, Cross-Platform
package testbench

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Underh0st/kinetix-contexthunter/internal/correlator"
	"github.com/Underh0st/kinetix-contexthunter/internal/scope"
	"github.com/Underh0st/kinetix-contexthunter/internal/validator"
)

func TestFullContextHunterBenchmarkSLA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	outDir := t.TempDir()
	summary, err := RunFullBenchmark(ctx, outDir)
	if err != nil {
		t.Fatalf("RunFullBenchmark failed: %v", err)
	}

	t.Logf("Fingerprint Precision: %.2f%% | Recall: %.2f%% | F1: %.2f%% (TP=%d, FP=%d, FN=%d)",
		summary.FingerprintPrecision*100, summary.FingerprintRecall*100, summary.FingerprintF1*100,
		summary.TruePositivesCPE, summary.FalsePositivesCPE, summary.FalseNegativesCPE)
	t.Logf("WAF Detection Accuracy: %.2f%% | WAF False Positives: %d",
		summary.WAFDetectionAccuracy*100, summary.WAFFalsePositives)
	t.Logf("Contextual CVE Tier Accuracy: %.2f%% (%d/%d)",
		summary.ContextualAccuracy*100, summary.ContextualTierMatches, summary.ContextualTierTotal)
	t.Logf("Scope Violations Blocked: %d | Adaptive 429 Backoffs: %d | Zero-Mutation Verified: %v",
		summary.ScopeViolationsBlocked, summary.RateLimitBackoffs, summary.ZeroMutationVerified)

	// SLA 1: Fingerprinting accuracy >= 90%
	if summary.FingerprintPrecision < 0.90 || summary.FingerprintRecall < 0.90 {
		t.Errorf("SLA violation: expected fingerprint precision/recall >= 0.90, got precision=%.2f, recall=%.2f",
			summary.FingerprintPrecision, summary.FingerprintRecall)
	}

	// SLA 2: Zero WAF false positives
	if summary.WAFFalsePositives != 0 {
		t.Errorf("SLA violation: expected 0 WAF false positives, got %d", summary.WAFFalsePositives)
	}
	if summary.WAFDetectionAccuracy < 1.0 {
		t.Errorf("SLA violation: expected 100%% WAF classification accuracy, got %.2f", summary.WAFDetectionAccuracy)
	}

	// SLA 3: Contextual CVE Engine accurately distinguishes vulnerable-exposed vs patched vs WAF-blocked
	if summary.ContextualAccuracy < 1.0 {
		t.Errorf("SLA violation: expected 100%% contextual tier match, got %.2f (%d/%d)",
			summary.ContextualAccuracy, summary.ContextualTierMatches, summary.ContextualTierTotal)
	}

	// SLA 4: Zero-Mutation Verification & Scope Enforcement
	if !summary.ZeroMutationVerified {
		t.Errorf("SLA violation: target state mutated during active PoC validation")
	}
	if summary.ScopeViolationsBlocked < 2 {
		t.Errorf("SLA violation: expected Scope Guard to block out-of-scope requests, got %d", summary.ScopeViolationsBlocked)
	}
	if summary.RateLimitBackoffs < 1 {
		t.Errorf("SLA violation: expected adaptive backoff on HTTP 429, got %d", summary.RateLimitBackoffs)
	}
}

func TestPoCGateAndZeroMutationGuard(t *testing.T) {
	ctx := context.Background()
	vDisabled := validator.NewValidator(http.DefaultClient, false, "QA")
	finding := correlator.ContextualFinding{
		CVEID:     "CVE-2023-51467",
		TargetURL: "http://127.0.0.1:8080",
		Tier:      "HIGH",
		SafeProbe: correlator.SafeProbeTemplate{
			Method: "GET",
			Path:   "/health",
		},
	}

	// Verify PoC is blocked when --enable-poc is false
	if _, err := vDisabled.ValidateFinding(ctx, finding); err != validator.ErrPoCDisabled {
		t.Fatalf("expected ErrPoCDisabled when --enable-poc is false, got %v", err)
	}

	// Verify mutating HTTP verbs (DELETE/PUT/POST) are rejected even when --enable-poc is true
	vEnabled := validator.NewValidator(http.DefaultClient, true, "QA")
	finding.SafeProbe.Method = http.MethodDelete
	if _, err := vEnabled.ValidateFinding(ctx, finding); err == nil {
		t.Fatalf("expected error when attempting DELETE verb in Phase 5 SafePoC")
	}

	// Verify TransportGuard blocks out-of-scope hosts
	g, err := scope.NewTransportGuard(scope.Policy{
		AllowedHosts:  []string{"*.authorized.example"},
		ExcludedHosts: []string{"billing.authorized.example"},
	}, http.DefaultTransport)
	if err != nil {
		t.Fatal(err)
	}
	client := g.NewScopedClient(2 * time.Second)
	if _, err := client.Get("https://billing.authorized.example/api"); err == nil {
		t.Fatalf("expected excluded host billing.authorized.example to be blocked")
	}
	if _, err := client.Get("https://evil.unscoped.org/api"); err == nil {
		t.Fatalf("expected out-of-scope host evil.unscoped.org to be blocked")
	}
}
