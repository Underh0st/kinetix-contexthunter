// language: Go, file: internal/waf/profiler.go, target: Go 1.22+, Cross-Platform
package waf

import (
	"context"
	"net/http"
	"strings"
)

type VectorType string

const (
	VectorQueryKeywords        VectorType = "query_string_sqli_keywords"
	VectorPathTraversalEncoded VectorType = "path_traversal_url_encoded"
	VectorJSONNestedObjects    VectorType = "json_body_nested_objects"
	VectorCustomHeaders        VectorType = "custom_headers_inspection"
)

type Profile struct {
	TargetURL            string                 `json:"target_url"`
	Detected             bool                   `json:"detected"`
	Vendor               string                 `json:"vendor"`           // none, modsecurity, cloudflare, aws_waf
	EnforcementMode      string                 `json:"enforcement_mode"` // monitor, block_immediate, rate_limit
	ParanoiaLevel        int                    `json:"paranoia_level"`
	PermissivenessMatrix map[VectorType]float64 `json:"permissiveness_matrix"`
}

type Profiler struct {
	Client *http.Client
}

func NewProfiler(client *http.Client) *Profiler {
	return &Profiler{Client: client}
}

// Characterize executes benign syntactic probes to determine WAF vendor and vector permeability.
func (p *Profiler) Characterize(ctx context.Context, baseURL string) (*Profile, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	prof := &Profile{
		TargetURL:       baseURL,
		Detected:        false,
		Vendor:          "none",
		EnforcementMode: "none",
		ParanoiaLevel:   0,
		PermissivenessMatrix: map[VectorType]float64{
			VectorQueryKeywords:        1.0,
			VectorPathTraversalEncoded: 1.0,
			VectorJSONNestedObjects:    1.0,
			VectorCustomHeaders:        1.0,
		},
	}

	// 1. Baseline probe
	baseResp, err := p.sendProbe(ctx, baseURL+"/?ctx_id=10042", nil)
	if err != nil {
		return nil, err
	}
	baseResp.Body.Close()
	p.identifyVendorFromHeaders(baseResp.Header, prof)

	// 2. Benign Query Operator / Keyword Probe (?ctx_id=10043-1&filter=benign_select_marker)
	qResp, err := p.sendProbe(ctx, baseURL+"/?ctx_id=10043-1&filter=benign_select_marker", nil)
	if err == nil {
		qResp.Body.Close()
		p.identifyVendorFromHeaders(qResp.Header, prof)
		if qResp.StatusCode == http.StatusForbidden || qResp.StatusCode == http.StatusNotAcceptable {
			prof.Detected = true
			prof.EnforcementMode = "block_immediate"
			prof.PermissivenessMatrix[VectorQueryKeywords] = 0.05
			if prof.ParanoiaLevel < 3 {
				prof.ParanoiaLevel = 3
			}
		}
	}

	// 3. Benign Normalized Relative Path Probe (/?asset=static/./robots.txt&norm=..%2fstatic)
	pathResp, err := p.sendProbe(ctx, baseURL+"/?asset=..%2fstatic%2frobots.txt", nil)
	if err == nil {
		pathResp.Body.Close()
		p.identifyVendorFromHeaders(pathResp.Header, prof)
		if pathResp.StatusCode == http.StatusForbidden || pathResp.StatusCode == http.StatusNotAcceptable {
			prof.Detected = true
			prof.EnforcementMode = "block_immediate"
			prof.PermissivenessMatrix[VectorPathTraversalEncoded] = 0.05
		} else if prof.Detected {
			prof.PermissivenessMatrix[VectorPathTraversalEncoded] = 0.90
		}
	}

	// 4. Benign Custom Routing Header Probe
	hdrResp, err := p.sendProbe(ctx, baseURL+"/?ctx_id=10042", map[string]string{
		"X-Original-Context": "/api/v1/health",
		"Content-Type":       "application/json",
	})
	if err == nil {
		hdrResp.Body.Close()
		p.identifyVendorFromHeaders(hdrResp.Header, prof)
		if hdrResp.StatusCode == http.StatusForbidden {
			prof.Detected = true
			prof.PermissivenessMatrix[VectorCustomHeaders] = 0.10
		} else if prof.Detected {
			prof.PermissivenessMatrix[VectorCustomHeaders] = 0.95
			prof.PermissivenessMatrix[VectorJSONNestedObjects] = 0.92
		}
	}

	return prof, nil
}

func (p *Profiler) identifyVendorFromHeaders(h http.Header, prof *Profile) {
	wafHdr := strings.ToLower(h.Get("X-WAF-Engine"))
	serverHdr := strings.ToLower(h.Get("Server"))
	cfRay := h.Get("CF-Ray")
	amznErr := h.Get("X-Amzn-Errortype")

	switch {
	case strings.Contains(wafHdr, "modsecurity") || strings.Contains(serverHdr, "mod_security"):
		prof.Detected = true
		prof.Vendor = "modsecurity"
		if strings.Contains(wafHdr, "pl3") {
			prof.ParanoiaLevel = 3
		} else if prof.ParanoiaLevel == 0 {
			prof.ParanoiaLevel = 1
		}
	case cfRay != "" || strings.Contains(serverHdr, "cloudflare"):
		prof.Detected = true
		prof.Vendor = "cloudflare"
	case amznErr != "" || h.Get("X-Amz-Cf-Id") != "":
		prof.Detected = true
		prof.Vendor = "aws_waf"
	}
}

func (p *Profiler) sendProbe(ctx context.Context, targetURL string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return p.Client.Do(req)
}
