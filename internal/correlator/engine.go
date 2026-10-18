// language: Go, file: internal/correlator/engine.go, target: Go 1.22+, Cross-Platform
package correlator

import (
	"fmt"
	"math"

	"github.com/Underh0st/kinetix-contexthunter/internal/waf"
)

// SafeProbeTemplate defines a strictly read-only, non-destructive verification request.
type SafeProbeTemplate struct {
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	Headers        map[string]string `json:"headers"`
	MaxReadBytes   int64             `json:"max_read_bytes"`
	ExpectedStatus int               `json:"expected_status"`
	ExpectedMarker string            `json:"expected_marker"`
}

// CVEPreconditionSpec enriches an NVD CVE record with contextual requirements.
type CVEPreconditionSpec struct {
	CVEID            string            `json:"cve_id"`
	Title            string            `json:"title"`
	AffectedCPE      string            `json:"affected_cpe"`
	PatchedCPE       string            `json:"patched_cpe"`
	RequiredEndpoint string            `json:"required_endpoint"`
	RequiredVector   waf.VectorType    `json:"required_vector"`
	RequiresAuth     bool              `json:"requires_auth"`
	BaseCVSS         float64           `json:"base_cvss"`
	SafeProbe        SafeProbeTemplate `json:"safe_probe"`
	Remediation      string            `json:"remediation"`
}

// TargetContext consolidates telemetry from Phases 1, 2, and 4.
type TargetContext struct {
	TargetURL            string
	DetectedCPEs         map[string]float64
	ExposedEndpoints     map[string]int
	WAF                  *waf.Profile
	MaxUserEnumConf      float64
	SelfRegistrationOpen bool
}

// ContextualFinding holds the prioritized correlation output.
type ContextualFinding struct {
	CVEID            string            `json:"cve_id"`
	Title            string            `json:"title"`
	TargetURL        string            `json:"target_url"`
	AffectedCPE      string            `json:"affected_cpe"`
	Endpoint         string            `json:"endpoint"`
	BaseCVSS         float64           `json:"base_cvss"`
	ProbabilityScore float64           `json:"probability_score"` // [0.0 - 1.0]
	ContextualRisk   float64           `json:"contextual_risk"`   // [0.0 - 100.0]
	Tier             string            `json:"tier"`              // HIGH, MEDIUM, LOW
	FactorBreakdown  map[string]float64 `json:"factor_breakdown"`
	BottleneckReason string            `json:"bottleneck_reason"`
	AttackRoute      []string          `json:"attack_route"`
	SafeProbe        SafeProbeTemplate `json:"safe_probe"`
	Remediation      string            `json:"remediation"`
}

// DefaultCatalog provides the offline contextual CVE knowledge base.
func DefaultCatalog() []CVEPreconditionSpec {
	return []CVEPreconditionSpec{
		{
			CVEID:            "CVE-2023-51467",
			Title:            "Apache OFBiz Pre-Auth Endpoint Exposure & Auth Bypass Vector",
			AffectedCPE:      "cpe:2.3:a:apache:ofbiz:18.12.09:*:*:*:*:*:*:*",
			PatchedCPE:       "cpe:2.3:a:apache:ofbiz:18.12.12:*:*:*:*:*:*:*",
			RequiredEndpoint: "/webtools/control/main",
			RequiredVector:   waf.VectorQueryKeywords,
			RequiresAuth:     false,
			BaseCVSS:         9.8,
			SafeProbe: SafeProbeTemplate{
				Method:         "GET",
				Path:           "/webtools/control/main?ctx_verify=1",
				Headers:        map[string]string{"Accept": "text/html"},
				MaxReadBytes:   256,
				ExpectedStatus: 200,
				ExpectedMarker: "OFBiz:18.12.09:AuthBypassReady",
			},
			Remediation: "Upgrade Apache OFBiz to >= 18.12.12 and restrict /webtools/* at the reverse proxy layer.",
		},
		{
			CVEID:            "CVE-2024-29847",
			Title:            "OWASP crAPI BOLA / Mechanic Report Metadata Exposure",
			AffectedCPE:      "cpe:2.3:a:owasp:crapi:1.2.0:*:*:*:*:*:*:*",
			RequiredEndpoint: "/workshop/api/mechanic/receive_report",
			RequiredVector:   waf.VectorJSONNestedObjects,
			RequiresAuth:     true,
			BaseCVSS:         8.1,
			SafeProbe: SafeProbeTemplate{
				Method:         "GET",
				Path:           "/workshop/api/mechanic/receive_report?report_id=1",
				Headers:        map[string]string{"Accept": "application/json"},
				MaxReadBytes:   256,
				ExpectedStatus: 200,
				ExpectedMarker: `"report_id":1`,
			},
			Remediation: "Enforce object-level ownership checks comparing JWT subject against report owner ID.",
		},
		{
			CVEID:            "CVE-2024-31905",
			Title:            "OWASP Juice Shop Exposed Configuration & Unauthenticated API Search Vector",
			AffectedCPE:      "cpe:2.3:a:owasp:juice_shop:16.2.1:*:*:*:*:*:*:*",
			RequiredEndpoint: "/rest/products/search",
			RequiredVector:   waf.VectorQueryKeywords,
			RequiresAuth:     false,
			BaseCVSS:         7.5,
			SafeProbe: SafeProbeTemplate{
				Method:         "GET",
				Path:           "/rest/products/search?q=apple",
				Headers:        map[string]string{"Accept": "application/json"},
				MaxReadBytes:   256,
				ExpectedStatus: 200,
				ExpectedMarker: `"status":"success"`,
			},
			Remediation: "Parameterize search queries and disable public access to /ftp/*.bak backup manifests.",
		},
		{
			CVEID:            "CVE-2023-38408",
			Title:            "Legacy Query Parameter Injection on PHP/DVWA Endpoint",
			AffectedCPE:      "cpe:2.3:a:dvwa:dvwa:2.4:*:*:*:*:*:*:*",
			RequiredEndpoint: "/vulnerabilities/sqli/",
			RequiredVector:   waf.VectorQueryKeywords,
			RequiresAuth:     false,
			BaseCVSS:         8.8,
			SafeProbe: SafeProbeTemplate{
				Method:         "GET",
				Path:           "/vulnerabilities/sqli/?id=1",
				Headers:        map[string]string{"Accept": "text/html"},
				MaxReadBytes:   256,
				ExpectedStatus: 200,
				ExpectedMarker: "Vulnerability: SQL Injection",
			},
			Remediation: "Maintain ModSecurity CRS Paranoia Level 3 blocking and migrate raw queries to prepared statements.",
		},
		{
			CVEID:            "CVE-2022-31129",
			Title:            "Moment.js 2.29.1 Inefficient Regular Expression Complexity on Date/Locale API",
			AffectedCPE:      "cpe:2.3:a:momentjs:moment:2.29.1:*:*:*:*:*:*:*",
			RequiredEndpoint: "/api/general/idioma/idioma-actual",
			RequiredVector:   waf.VectorJSONNestedObjects,
			RequiresAuth:     false,
			BaseCVSS:         7.5,
			SafeProbe: SafeProbeTemplate{
				Method:         "GET",
				Path:           "/api/general/idioma/idioma-actual",
				Headers:        map[string]string{"Accept": "application/json"},
				MaxReadBytes:   256,
				ExpectedStatus: 200,
				ExpectedMarker: `"idioma"`,
			},
			Remediation: "Upgrade Moment.js to >= 2.29.4 or migrate date parsing to Day.js / Luxon.",
		},
		{
			CVEID:            "CVE-2021-44790",
			Title:            "Apache HTTP Server 2.4.37 mod_lua Buffer Overflow (Backport Verification)",
			AffectedCPE:      "cpe:2.3:a:apache:http_server:2.4.37:*:*:*:*:*:*:*",
			PatchedCPE:       "cpe:2.3:o:almalinux:almalinux:8.0:*:*:*:*:*:*:*",
			RequiredEndpoint: "/api/general/login/sesion-valida",
			RequiredVector:   waf.VectorCustomHeaders,
			RequiresAuth:     false,
			BaseCVSS:         9.8,
			SafeProbe: SafeProbeTemplate{
				Method:         "GET",
				Path:           "/api/general/login/sesion-valida",
				Headers:        map[string]string{"Accept": "application/json"},
				MaxReadBytes:   256,
				ExpectedStatus: 200,
				ExpectedMarker: `"sesion"`,
			},
			Remediation: "Verified enterprise backport patch via AlmaLinux 8 httpd build; keep distro security updates active.",
		},
	}
}

// BuildAcademyLabSpec constructs a contextual precondition specification for a detected PortSwigger Academy lab surface.
func BuildAcademyLabSpec(cweID, title, targetCPE, endpoint string) CVEPreconditionSpec {
	return CVEPreconditionSpec{
		CVEID:            cweID,
		Title:            title,
		AffectedCPE:      targetCPE,
		RequiredEndpoint: endpoint,
		RequiredVector:   waf.VectorQueryKeywords,
		RequiresAuth:     false,
		BaseCVSS:         8.8,
		SafeProbe: SafeProbeTemplate{
			Method:         "GET",
			Path:           endpoint,
			Headers:        map[string]string{"Accept": "text/html"},
			MaxReadBytes:   256,
			ExpectedStatus: 200,
			ExpectedMarker: "html",
		},
		Remediation: "Apply strict server-side input validation, parameterized queries, and context-aware output encoding.",
	}
}

// EvaluateAll correlates the target context against the CVE catalog and ranks findings.
func EvaluateAll(catalog []CVEPreconditionSpec, ctx TargetContext) []ContextualFinding {
	var findings []ContextualFinding
	for _, spec := range catalog {
		f := EvaluateSingle(spec, ctx)
		findings = append(findings, f)
	}
	return findings
}

func EvaluateSingle(spec CVEPreconditionSpec, ctx TargetContext) ContextualFinding {
	f := ContextualFinding{
		CVEID:           spec.CVEID,
		Title:           spec.Title,
		TargetURL:       ctx.TargetURL,
		AffectedCPE:     spec.AffectedCPE,
		Endpoint:        spec.RequiredEndpoint,
		BaseCVSS:        spec.BaseCVSS,
		FactorBreakdown: make(map[string]float64),
		SafeProbe:       spec.SafeProbe,
		Remediation:     spec.Remediation,
	}

	// 1. Version & Patch Check (V_match)
	if spec.PatchedCPE != "" {
		if patchedConf, isPatched := ctx.DetectedCPEs[spec.PatchedCPE]; isPatched && patchedConf >= 0.5 {
			f.FactorBreakdown["V_match"] = 0.0
			f.Tier = "LOW"
			f.BottleneckReason = fmt.Sprintf("Patched version detected (%s, conf=%.2f)", spec.PatchedCPE, patchedConf)
			return f
		}
	}

	vMatch, exists := ctx.DetectedCPEs[spec.AffectedCPE]
	if !exists || vMatch == 0 {
		f.FactorBreakdown["V_match"] = 0.0
		f.Tier = "LOW"
		f.BottleneckReason = "Affected CPE not present on target"
		return f
	}
	f.FactorBreakdown["V_match"] = vMatch

	// 2. WAF Vector Permeability (W_pass)
	wPass := 1.0
	wafVendor := "none"
	if ctx.WAF != nil {
		wafVendor = ctx.WAF.Vendor
		if val, ok := ctx.WAF.PermissivenessMatrix[spec.RequiredVector]; ok {
			wPass = val
		}
	}
	f.FactorBreakdown["W_pass"] = wPass

	// 3. API Surface Exposure (E_exp)
	eExp := 0.0
	if status, ok := ctx.ExposedEndpoints[spec.RequiredEndpoint]; ok {
		switch {
		case status >= 200 && status < 300:
			eExp = 1.0
		case status == 401 || status == 405 || status == 422:
			eExp = 0.65
		case status == 403:
			eExp = 0.10 // Blocked by reverse proxy or WAF ACL
		}
	}
	f.FactorBreakdown["E_exp"] = eExp

	// 4. Authentication & Identity Viability (A_viable)
	aViable := 1.0
	if spec.RequiresAuth {
		if ctx.SelfRegistrationOpen {
			aViable = 0.95
		} else if ctx.MaxUserEnumConf > 0 {
			aViable = math.Max(0.30, ctx.MaxUserEnumConf)
		} else {
			aViable = 0.15
		}
	}
	f.FactorBreakdown["A_viable"] = aViable

	pExec := vMatch * wPass * eExp * aViable
	f.ProbabilityScore = math.Round(pExec*1000) / 1000
	f.ContextualRisk = math.Round((pExec*(spec.BaseCVSS/10.0))*1000) / 10

	switch {
	case pExec >= 0.70:
		f.Tier = "HIGH"
		f.BottleneckReason = "Exposed endpoint, vulnerable version confirmed, and vector permitted by WAF"
	case pExec >= 0.35:
		f.Tier = "MEDIUM"
		if wPass < 0.40 {
			f.BottleneckReason = fmt.Sprintf("WAF (%s) actively filters vector %s (W_pass=%.2f)", wafVendor, spec.RequiredVector, wPass)
		} else {
			f.BottleneckReason = "Partial exposure or requires secondary authentication factor"
		}
	default:
		f.Tier = "LOW"
		if wPass < 0.20 {
			f.BottleneckReason = fmt.Sprintf("Blocked by WAF (%s) on vector %s (W_pass=%.2f)", wafVendor, spec.RequiredVector, wPass)
		} else if eExp <= 0.15 {
			f.BottleneckReason = fmt.Sprintf("Required endpoint %s is not exposed or blocked (403/404)", spec.RequiredEndpoint)
		} else {
			f.BottleneckReason = "Contextual constraints prevent exploitation"
		}
	}

	f.AttackRoute = []string{
		fmt.Sprintf("Tech[%s](%.2f)", spec.AffectedCPE, vMatch),
		fmt.Sprintf("WAF[%s](%.2f)", wafVendor, wPass),
		fmt.Sprintf("Endpoint[%s](%.2f)", spec.RequiredEndpoint, eExp),
		fmt.Sprintf("AuthViability(%.2f)", aViable),
		fmt.Sprintf("CVE[%s -> P_exec=%.2f (%s)]", spec.CVEID, f.ProbabilityScore, f.Tier),
	}

	return f
}
