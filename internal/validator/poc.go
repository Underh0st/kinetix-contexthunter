// language: Go, file: internal/validator/poc.go, target: Go 1.22+, Cross-Platform
package validator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Underh0st/kinetix-contexthunter/internal/correlator"
)

var (
	ErrPoCDisabled      = errors.New("active validation disabled: pass --enable-poc to authorize non-destructive checks")
	ErrMutatingVerb     = errors.New("zero-mutation policy violation: only GET, HEAD, and OPTIONS are permitted in Phase 5")
	ErrLowTierSkipped   = errors.New("finding tier is below HIGH threshold; active validation skipped to preserve stealth")
)

type Evidence struct {
	CVEID           string `json:"cve_id"`
	TargetURL       string `json:"target_url"`
	Validated       bool   `json:"validated"`
	TimestampUTC    string `json:"timestamp_utc"`
	RequestLine     string `json:"request_line"`
	StatusCode      int    `json:"status_code"`
	BytesRead       int    `json:"bytes_read"`
	LatencyMs       int64  `json:"latency_ms"`
	MatchedSnippet  string `json:"matched_snippet"`
	EvidenceSHA256  string `json:"evidence_sha256"`
	ReproCurl       string `json:"repro_curl"`
}

type Validator struct {
	Client       *http.Client
	EnablePoC    bool
	BountyHeader string
}

func NewValidator(client *http.Client, enablePoC bool, bountyHeader string) *Validator {
	return &Validator{
		Client:       client,
		EnablePoC:    enablePoC,
		BountyHeader: bountyHeader,
	}
}

// ValidateFinding executes a bounded, zero-mutation read probe for HIGH probability findings.
func (v *Validator) ValidateFinding(ctx context.Context, finding correlator.ContextualFinding) (*Evidence, error) {
	if !v.EnablePoC {
		return nil, ErrPoCDisabled
	}
	if finding.Tier != "HIGH" {
		return nil, ErrLowTierSkipped
	}

	probe := finding.SafeProbe
	switch probe.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		return nil, fmt.Errorf("%w: %s", ErrMutatingVerb, probe.Method)
	}

	fullURL := strings.TrimRight(finding.TargetURL, "/") + probe.Path
	req, err := http.NewRequestWithContext(ctx, probe.Method, fullURL, nil)
	if err != nil {
		return nil, err
	}

	for k, val := range probe.Headers {
		req.Header.Set(k, val)
	}
	maxRead := probe.MaxReadBytes
	if maxRead <= 0 || maxRead > 256 {
		maxRead = 256
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", maxRead-1))

	start := time.Now()
	resp, err := v.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxRead))
	if err != nil {
		return nil, err
	}
	latency := time.Since(start).Milliseconds()
	bodyText := string(bodyBytes)

	statusOK := resp.StatusCode == probe.ExpectedStatus ||
		(probe.ExpectedStatus == http.StatusOK && resp.StatusCode == http.StatusPartialContent)
	markerOK := probe.ExpectedMarker == "" || strings.Contains(strings.ToLower(bodyText), strings.ToLower(probe.ExpectedMarker))

	validated := statusOK && markerOK
	rawTranscript := fmt.Sprintf(
		"REQ: %s %s\nRANGE: bytes=0-%d\nSTATUS: %d\nBODY_SAMPLE: %s",
		probe.Method, fullURL, maxRead-1, resp.StatusCode, bodyText,
	)
	sum := sha256.Sum256([]byte(rawTranscript))

	curlCmd := fmt.Sprintf(
		"curl -i -s -X %s -H 'Range: bytes=0-%d' '%s'",
		probe.Method, maxRead-1, fullURL,
	)

	return &Evidence{
		CVEID:          finding.CVEID,
		TargetURL:      finding.TargetURL,
		Validated:      validated,
		TimestampUTC:   time.Now().UTC().Format(time.RFC3339),
		RequestLine:    fmt.Sprintf("%s %s HTTP/1.1", probe.Method, probe.Path),
		StatusCode:     resp.StatusCode,
		BytesRead:      len(bodyBytes),
		LatencyMs:      latency,
		MatchedSnippet: probe.ExpectedMarker,
		EvidenceSHA256: hex.EncodeToString(sum[:]),
		ReproCurl:      curlCmd,
	}, nil
}
