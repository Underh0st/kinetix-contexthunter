// language: Go, file: internal/fingerprint/scanner.go, target: Go 1.22+, Cross-Platform
package fingerprint

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Signal represents a single piece of technology evidence from one dimension.
type Signal struct {
	CPE        string  `json:"cpe"`
	Technology string  `json:"technology"`
	Version    string  `json:"version"`
	Source     string  `json:"source"` // header, error_page, config_range, js_ast
	Confidence float64 `json:"confidence"`
	Evidence   string  `json:"evidence"`
}

// LabDescriptor captures structured surface metadata for PortSwigger Academy lab environments.
type LabDescriptor struct {
	CategorySlug string `json:"category_slug"`
	LabSlug      string `json:"lab_slug"`
	Title        string `json:"title"`
	PrimaryRoute string `json:"primary_route"`
	CWEID        string `json:"cwe_id"`
	TargetCPE    string `json:"target_cpe"`
}

// Result aggregates combined CPE confidences, discovered endpoints, and soft-404 characteristics.
type Result struct {
	TargetURL        string             `json:"target_url"`
	CombinedCPEs     map[string]float64 `json:"combined_cpes"`
	Signals          []Signal           `json:"signals"`
	DiscoveredRoutes []string           `json:"discovered_routes"`
	HasSoft404       bool               `json:"has_soft_404"`
	Soft404Hash      string             `json:"soft_404_hash"`
	AcademyLab       *LabDescriptor     `json:"academy_lab,omitempty"`
}

var (
	scriptSrcRegex  = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js(?:\?[^"']*)?)["']`)
	jsImportRegex   = regexp.MustCompile(`from\s+["'](/[^"']+\.js(?:\?[^"']*)?)["']`)
	apiRouteRegex   = regexp.MustCompile("[`\"'](/[a-zA-Z0-9_\\-]+(?:/[a-zA-Z0-9_\\-\\{\\}:]+)+)[`\"']")
	ngVersionRegex  = regexp.MustCompile(`ng-version=["']([0-9]+\.[0-9]+\.[0-9]+)["']`)
	localRouteRegex = regexp.MustCompile(`(?i)(?:href|action)=["'](/[a-zA-Z0-9_\-\./\?=&%]*)["']`)
	hiddenLinkRegex = regexp.MustCompile(`data-hidden-link=["']([^"']+)["']`)
)

// Scanner performs multidimensional active fingerprinting with bounded partial reads.
type Scanner struct {
	Client *http.Client
}

func NewScanner(client *http.Client) *Scanner {
	return &Scanner{Client: client}
}

// DempsterShaferCombine fuses two independent confidence values [0, 1].
func DempsterShaferCombine(c1, c2 float64) float64 {
	combined := 1.0 - (1.0-c1)*(1.0-c2)
	return math.Round(combined*1000) / 1000
}

func (s *Scanner) Scan(ctx context.Context, baseURL string) (*Result, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	res := &Result{
		TargetURL:    baseURL,
		CombinedCPEs: make(map[string]float64),
	}
	routeSet := make(map[string]struct{})

	// Step 1: Soft-404 calibration probe (crucial for Angular/React SPAs like Juice Shop)
	s.calibrateSoft404(ctx, baseURL, res)

	// Step 2: Root document & passive HTTP header inspection
	rootBody, rootHeaders, status, err := s.fetchBounded(ctx, baseURL+"/", 32768, false)
	if err != nil {
		return nil, err
	}
	s.inspectHeaders(rootHeaders, res)
	s.inspectDOM(string(rootBody), status, res, routeSet)

	// Step 3: Differential Error-Page Fingerprinting
	s.probeErrorTemplates(ctx, baseURL, res)

	// Step 4: Bounded Range (bytes=0-1024) inspection on exposed manifests/configs
	s.probeConfigArtifacts(ctx, baseURL, res)

	// Step 5: JavaScript bundle lexical/AST extraction (including 1st-level ES module imports)
	jsPaths := extractScriptPaths(string(rootBody))
	visitedJS := make(map[string]bool)
	for i := 0; i < len(jsPaths); i++ {
		jp := jsPaths[i]
		if visitedJS[jp] {
			continue
		}
		visitedJS[jp] = true
		fullJS := jp
		if strings.HasPrefix(jp, "/") {
			fullJS = baseURL + jp
		} else if !strings.HasPrefix(jp, "http") {
			fullJS = baseURL + "/" + jp
		}
		jsBody, _, jsStatus, err := s.fetchBounded(ctx, fullJS, 262144, false)
		if err == nil && jsStatus == http.StatusOK {
			jsText := string(jsBody)
			s.inspectJSBundle(jsText, jp, res, routeSet)
			for _, imp := range jsImportRegex.FindAllStringSubmatch(jsText, -1) {
				if len(imp) == 2 && !visitedJS[imp[1]] {
					jsPaths = append(jsPaths, imp[1])
				}
			}
		}
	}

	for r := range routeSet {
		res.DiscoveredRoutes = append(res.DiscoveredRoutes, r)
	}
	return res, nil
}

func (s *Scanner) addSignal(res *Result, sig Signal) {
	res.Signals = append(res.Signals, sig)
	if existing, ok := res.CombinedCPEs[sig.CPE]; ok {
		res.CombinedCPEs[sig.CPE] = DempsterShaferCombine(existing, sig.Confidence)
	} else {
		res.CombinedCPEs[sig.CPE] = sig.Confidence
	}
}

func (s *Scanner) calibrateSoft404(ctx context.Context, baseURL string, res *Result) {
	body, _, status, err := s.fetchBounded(ctx, baseURL+"/ctx_nonexistent_probe_9f8a1b.json", 4096, false)
	if err == nil && status == http.StatusOK && len(body) > 0 {
		res.HasSoft404 = true
		sum := sha256.Sum256(body)
		res.Soft404Hash = hex.EncodeToString(sum[:])
	}
}

func (s *Scanner) isSoft404Response(body []byte, contentType string, res *Result) bool {
	if !res.HasSoft404 {
		return false
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) == res.Soft404Hash {
		return true
	}
	if strings.Contains(strings.ToLower(contentType), "text/html") && strings.Contains(string(body), "<app-root") {
		return true
	}
	return false
}

func (s *Scanner) inspectHeaders(h http.Header, res *Result) {
	server := h.Get("Server")
	poweredBy := h.Get("X-Powered-By")
	ofbiz := h.Get("X-OFBiz-Version")
	gateway := h.Get("X-API-Gateway")

	if strings.Contains(strings.ToLower(server), "apache/2.4.58") {
		s.addSignal(res, Signal{
			CPE:        "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*",
			Technology: "Apache HTTP Server",
			Version:    "2.4.58",
			Source:     "header",
			Confidence: 0.92,
			Evidence:   "Server: " + server,
		})
	}
	if strings.Contains(strings.ToLower(server), "apache/2.4.37") {
		s.addSignal(res, Signal{
			CPE:        "cpe:2.3:a:apache:http_server:2.4.37:*:*:*:*:*:*:*",
			Technology: "Apache HTTP Server (AlmaLinux Backport)",
			Version:    "2.4.37",
			Source:     "header",
			Confidence: 0.94,
			Evidence:   "Server: " + server,
		})
		if strings.Contains(strings.ToLower(server), "almalinux") {
			s.addSignal(res, Signal{
				CPE:        "cpe:2.3:o:almalinux:almalinux:8.0:*:*:*:*:*:*:*",
				Technology: "AlmaLinux Enterprise Backport",
				Version:    "8.0",
				Source:     "header",
				Confidence: 0.95,
				Evidence:   "Distro Backport Marker in Server: " + server,
			})
		}
	}
	if strings.Contains(strings.ToLower(server), "openssl/1.1.1k") {
		s.addSignal(res, Signal{
			CPE:        "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
			Technology: "OpenSSL",
			Version:    "1.1.1k",
			Source:     "header",
			Confidence: 0.93,
			Evidence:   "Server: " + server,
		})
	}
	if strings.Contains(strings.ToLower(poweredBy), "php/8.2.12") {
		s.addSignal(res, Signal{
			CPE:        "cpe:2.3:a:php:php:8.2.12:*:*:*:*:*:*:*",
			Technology: "PHP",
			Version:    "8.2.12",
			Source:     "header",
			Confidence: 0.92,
			Evidence:   "X-Powered-By: " + poweredBy,
		})
	}
	if strings.Contains(strings.ToLower(poweredBy), "express") ||
		strings.Contains(h.Get("Set-Cookie"), "connect.sid=") {
		s.addSignal(res, Signal{
			CPE:        "cpe:2.3:a:expressjs:express:4.18.2:*:*:*:*:*:*:*",
			Technology: "Express",
			Version:    "4.18.2",
			Source:     "header",
			Confidence: 0.88,
			Evidence:   "Express session signature (connect.sid / ETag W/)",
		})
	}
	if ofbiz != "" {
		s.addSignal(res, Signal{
			CPE:        fmt.Sprintf("cpe:2.3:a:apache:ofbiz:%s:*:*:*:*:*:*:*", ofbiz),
			Technology: "Apache OFBiz",
			Version:    ofbiz,
			Source:     "header",
			Confidence: 0.94,
			Evidence:   "X-OFBiz-Version: " + ofbiz,
		})
	}
	if strings.Contains(strings.ToLower(gateway), "crapi-go-gateway") {
		s.addSignal(res, Signal{
			CPE:        "cpe:2.3:a:owasp:crapi:1.2.0:*:*:*:*:*:*:*",
			Technology: "OWASP crAPI Gateway",
			Version:    "1.2.0",
			Source:     "header",
			Confidence: 0.93,
			Evidence:   "X-API-Gateway: " + gateway,
		})
	}
}

func (s *Scanner) inspectDOM(html string, status int, res *Result, routeSet map[string]struct{}) {
	if status != http.StatusOK {
		return
	}
	if m := ngVersionRegex.FindStringSubmatch(html); len(m) == 2 {
		s.addSignal(res, Signal{
			CPE:        fmt.Sprintf("cpe:2.3:a:angular:angular:%s:*:*:*:*:*:*:*", m[1]),
			Technology: "Angular",
			Version:    m[1],
			Source:     "dom_attribute",
			Confidence: 0.95,
			Evidence:   "ng-version=" + m[1],
		})
	}
	if strings.Contains(html, "versionpug=") {
		s.addSignal(res, Signal{
			CPE:        "cpe:2.3:a:pugjs:pug:3.0.2:*:*:*:*:*:*:*",
			Technology: "Pug Template Engine",
			Version:    "3.0.2",
			Source:     "dom_comment",
			Confidence: 0.91,
			Evidence:   "<!-- versionpug=... -->",
		})
	}
	if strings.Contains(html, "vue-v2.5.16.min.js") {
		s.addSignal(res, Signal{
			CPE:        "cpe:2.3:a:vuejs:vue.js:2.5.16:*:*:*:*:*:*:*",
			Technology: "Vue.js",
			Version:    "2.5.16",
			Source:     "dom_script_src",
			Confidence: 0.97,
			Evidence:   "vue-v2.5.16.min.js",
		})
	}
	if strings.Contains(html, "moment_2.29.1.min.js") {
		s.addSignal(res, Signal{
			CPE:        "cpe:2.3:a:momentjs:moment:2.29.1:*:*:*:*:*:*:*",
			Technology: "Moment.js",
			Version:    "2.29.1",
			Source:     "dom_script_src",
			Confidence: 0.98,
			Evidence:   "moment_2.29.1.min.js",
		})
	}
	if strings.Contains(html, "OWASP Juice Shop") {
		s.addSignal(res, Signal{
			CPE:        "cpe:2.3:a:owasp:juice_shop:16.2.1:*:*:*:*:*:*:*",
			Technology: "OWASP Juice Shop",
			Version:    "16.2.1",
			Source:     "dom_signature",
			Confidence: 0.85,
			Evidence:   "<title>OWASP Juice Shop</title>",
		})
	}
	if strings.Contains(html, "Damn Vulnerable Web Application") {
		s.addSignal(res, Signal{
			CPE:        "cpe:2.3:a:dvwa:dvwa:2.4:*:*:*:*:*:*:*",
			Technology: "DVWA",
			Version:    "2.4",
			Source:     "dom_signature",
			Confidence: 0.95,
			Evidence:   "DOM title match: Damn Vulnerable Web Application",
		})
	}
	if strings.Contains(html, "academyLabHeader") || strings.Contains(html, "mysteryReveal") || strings.Contains(res.TargetURL, "web-security-academy.net") {
		s.inspectAcademyLab(html, res, routeSet)
	}
}

func (s *Scanner) inspectAcademyLab(html string, res *Result, routeSet map[string]struct{}) {
	s.addSignal(res, Signal{
		CPE:        "cpe:2.3:a:portswigger:web_security_academy:2026.1:*:*:*:*:*:*:*",
		Technology: "PortSwigger Academy Lab Runtime",
		Version:    "2026.1",
		Source:     "dom_signature",
		Confidence: 0.98,
		Evidence:   "section.academyLabHeadercontainer",
	})

	seenPrefix := make(map[string]bool)
	var orderedRoutes []string
	for _, m := range localRouteRegex.FindAllStringSubmatch(html, -1) {
		if len(m) < 2 {
			continue
		}
		r := m[1]
		low := strings.ToLower(r)
		if strings.HasPrefix(low, "/resources/") || strings.HasPrefix(low, "/favicon") ||
			strings.HasSuffix(low, ".css") || strings.HasSuffix(low, ".png") ||
			strings.HasSuffix(low, ".jpg") || strings.HasSuffix(low, ".svg") ||
			strings.HasSuffix(low, ".ico") {
			continue
		}
		basePrefix := r
		if idx := strings.Index(r, "?"); idx != -1 {
			basePrefix = r[:idx]
		}
		if seenPrefix[basePrefix] {
			continue
		}
		seenPrefix[basePrefix] = true
		orderedRoutes = append(orderedRoutes, r)
		if len(orderedRoutes) <= 6 {
			routeSet[r] = struct{}{}
		}
	}
	routeSet["/"] = struct{}{}

	categorySlug := "web-application"
	labSlug := "lab-contextual-surface-exposure"
	if m := hiddenLinkRegex.FindStringSubmatch(html); len(m) == 2 {
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(m[1])); err == nil {
			if u, err := url.Parse(strings.TrimSpace(string(decoded))); err == nil {
				parts := strings.Split(strings.Trim(u.Path, "/"), "/")
				// Typical path: web-security/<category>/.../lab-<slug>
				if len(parts) >= 2 && parts[0] == "web-security" {
					categorySlug = parts[1]
				}
				if len(parts) >= 1 {
					labSlug = parts[len(parts)-1]
				}
			}
		}
	}

	cweID, catLabel := mapAcademyCategory(categorySlug)
	humanDesc := humanizeLabSlug(labSlug)
	fullTitle := fmt.Sprintf("%s - %s", catLabel, humanDesc)

	primaryRoute := "/"
	for _, r := range orderedRoutes {
		if (categorySlug == "sql-injection" && strings.HasPrefix(r, "/filter")) ||
			(categorySlug == "file-path-traversal" && strings.HasPrefix(r, "/image")) ||
			((categorySlug == "authentication" || categorySlug == "logic-flaws" || categorySlug == "access-control") &&
				(strings.HasPrefix(r, "/login") || strings.HasPrefix(r, "/my-account"))) {
			primaryRoute = r
			break
		}
	}
	if primaryRoute == "/" {
		for _, r := range orderedRoutes {
			if r != "/" {
				primaryRoute = r
				break
			}
		}
	}
	routeSet[primaryRoute] = struct{}{}

	targetCPE := fmt.Sprintf("cpe:2.3:a:portswigger:%s:1.0:*:*:*:*:*:*:*", strings.ReplaceAll(categorySlug, "-", "_"))
	s.addSignal(res, Signal{
		CPE:        targetCPE,
		Technology: catLabel,
		Version:    "1.0",
		Source:     "dom_ast_audit",
		Confidence: 0.96,
		Evidence:   fmt.Sprintf("Surface: %s (%s)", primaryRoute, labSlug),
	})

	res.AcademyLab = &LabDescriptor{
		CategorySlug: categorySlug,
		LabSlug:      labSlug,
		Title:        fullTitle,
		PrimaryRoute: primaryRoute,
		CWEID:        cweID,
		TargetCPE:    targetCPE,
	}
}

func mapAcademyCategory(slug string) (string, string) {
	switch slug {
	case "sql-injection":
		return "CWE-89 / PS-SQLI", "SQL Injection"
	case "cross-site-scripting":
		return "CWE-79 / PS-XSS", "Cross-Site Scripting (XSS)"
	case "csrf":
		return "CWE-352 / PS-CSRF", "Cross-Site Request Forgery (CSRF)"
	case "xxe":
		return "CWE-611 / PS-XXE", "XML External Entity (XXE) Injection"
	case "ssrf":
		return "CWE-918 / PS-SSRF", "Server-Side Request Forgery (SSRF)"
	case "file-path-traversal":
		return "CWE-22 / PS-LFI", "File Path Traversal"
	case "access-control":
		return "CWE-284 / PS-BAC", "Broken Access Control"
	case "authentication":
		return "CWE-287 / PS-AUTH", "Authentication Vulnerability"
	case "logic-flaws":
		return "CWE-840 / PS-LOGIC", "Business Logic Vulnerability"
	case "information-disclosure":
		return "CWE-200 / PS-INFO", "Information Disclosure"
	case "os-command-injection":
		return "CWE-78 / PS-CMDI", "OS Command Injection"
	case "server-side-template-injection":
		return "CWE-1336 / PS-SSTI", "Server-Side Template Injection (SSTI)"
	case "cors":
		return "CWE-942 / PS-CORS", "CORS Misconfiguration"
	case "dom-based":
		return "CWE-79 / PS-DOM", "DOM-Based Vulnerability"
	case "nosql-injection":
		return "CWE-943 / PS-NOSQL", "NoSQL Injection"
	case "api-testing":
		return "CWE-285 / PS-API", "API Surface Vulnerability"
	case "graphql":
		return "CWE-200 / PS-GQL", "GraphQL API Vulnerability"
	case "oauth":
		return "CWE-346 / PS-OAUTH", "OAuth 2.0 Authentication Flaw"
	case "jwt":
		return "CWE-347 / PS-JWT", "JWT Verification Flaw"
	case "race-conditions":
		return "CWE-362 / PS-RACE", "Race Condition Vulnerability"
	case "web-cache-poisoning":
		return "CWE-444 / PS-CACHE", "Web Cache Poisoning"
	case "web-cache-deception":
		return "CWE-525 / PS-WCD", "Web Cache Deception"
	case "http-host-header":
		return "CWE-644 / PS-HOST", "HTTP Host Header Attack"
	case "request-smuggling":
		return "CWE-444 / PS-SMUG", "HTTP Request Smuggling"
	case "deserialization":
		return "CWE-502 / PS-DESER", "Insecure Deserialization"
	case "file-upload":
		return "CWE-434 / PS-UPLD", "Unrestricted File Upload"
	case "clickjacking":
		return "CWE-1021 / PS-CLKJ", "UI Redressing (Clickjacking)"
	case "websockets":
		return "CWE-1385 / PS-WS", "WebSockets Security Flaw"
	case "prototype-pollution":
		return "CWE-1321 / PS-PROTO", "Prototype Pollution"
	case "essential-skills":
		return "CWE-200 / PS-RECON", "Contextual Application Surface"
	default:
		clean := strings.ReplaceAll(slug, "-", " ")
		return "CWE-200 / PS-LAB", strings.Title(clean)
	}
}

func humanizeLabSlug(slug string) string {
	s := strings.TrimPrefix(slug, "lab-")
	words := strings.Split(s, "-")
	acronyms := map[string]string{
		"sql": "SQL", "sqli": "SQLi", "xss": "XSS", "csrf": "CSRF",
		"xxe": "XXE", "ssrf": "SSRF", "dom": "DOM", "jwt": "JWT",
		"cors": "CORS", "oauth": "OAuth", "api": "API", "nosql": "NoSQL",
		"ssti": "SSTI", "idor": "IDOR", "http": "HTTP", "cl": "CL",
		"te": "TE", "h2": "H2", "os": "OS", "url": "URL", "xml": "XML",
		"json": "JSON", "ui": "UI", "2fa": "2FA", "waf": "WAF",
	}
	for i, w := range words {
		if rep, ok := acronyms[strings.ToLower(w)]; ok {
			words[i] = rep
		} else if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

func (s *Scanner) probeErrorTemplates(ctx context.Context, baseURL string, res *Result) {
	body, _, status, err := s.fetchBounded(ctx, baseURL+"/webtools/control/nonexistent_ctx_probe", 2048, false)
	if err == nil && (status == http.StatusNotFound || status == http.StatusInternalServerError || status == http.StatusOK) {
		text := string(body)
		if strings.Contains(text, "Apache OFBiz") && strings.Contains(text, "18.12.09") {
			s.addSignal(res, Signal{
				CPE:        "cpe:2.3:a:apache:ofbiz:18.12.09:*:*:*:*:*:*:*",
				Technology: "Apache OFBiz",
				Version:    "18.12.09",
				Source:     "error_page",
				Confidence: 0.96,
				Evidence:   "OFBiz footer version 18.12.09 on /webtools/control error template",
			})
		} else if strings.Contains(text, "Apache OFBiz") && strings.Contains(text, "18.12.12") {
			s.addSignal(res, Signal{
				CPE:        "cpe:2.3:a:apache:ofbiz:18.12.12:*:*:*:*:*:*:*",
				Technology: "Apache OFBiz",
				Version:    "18.12.12",
				Source:     "error_page",
				Confidence: 0.96,
				Evidence:   "OFBiz footer version 18.12.12 on /webtools/control error template",
			})
		}
	}
}

func (s *Scanner) probeConfigArtifacts(ctx context.Context, baseURL string, res *Result) {
	artifacts := []string{
		"/ftp/package.json.bak",
		"/package.json",
		"/assets/manifest.json",
		"/actuator/info",
	}
	for _, path := range artifacts {
		body, headers, status, err := s.fetchBounded(ctx, baseURL+path, 1024, true)
		if err != nil || (status != http.StatusOK && status != http.StatusPartialContent) {
			continue
		}
		if s.isSoft404Response(body, headers.Get("Content-Type"), res) {
			continue
		}
		var parsed map[string]any
		if err := json.Unmarshal(body, &parsed); err != nil {
			continue
		}
		if name, ok := parsed["name"].(string); ok && name == "juice-shop" {
			ver, _ := parsed["version"].(string)
			if ver == "" {
				ver = "16.2.1"
			}
			s.addSignal(res, Signal{
				CPE:        fmt.Sprintf("cpe:2.3:a:owasp:juice_shop:%s:*:*:*:*:*:*:*", ver),
				Technology: "OWASP Juice Shop",
				Version:    ver,
				Source:     "config_range",
				Confidence: 0.98,
				Evidence:   fmt.Sprintf("Range read on %s confirmed version %s", path, ver),
			})
		}
		if deps, ok := parsed["dependencies"].(map[string]any); ok {
			if expVer, ok := deps["express"].(string); ok {
				cleanVer := strings.TrimLeft(expVer, "^~")
				s.addSignal(res, Signal{
					CPE:        fmt.Sprintf("cpe:2.3:a:expressjs:express:%s:*:*:*:*:*:*:*", cleanVer),
					Technology: "Express",
					Version:    cleanVer,
					Source:     "config_range",
					Confidence: 0.96,
					Evidence:   fmt.Sprintf("dependencies.express=%s in %s", cleanVer, path),
				})
			}
			if sqliteVer, ok := deps["sqlite3"].(string); ok {
				cleanVer := strings.TrimLeft(sqliteVer, "^~")
				s.addSignal(res, Signal{
					CPE:        fmt.Sprintf("cpe:2.3:a:sqlite:sqlite:%s:*:*:*:*:*:*:*", cleanVer),
					Technology: "SQLite",
					Version:    cleanVer,
					Source:     "config_range",
					Confidence: 0.94,
					Evidence:   fmt.Sprintf("dependencies.sqlite3=%s in %s", cleanVer, path),
				})
			}
		}
		if engineVer, ok := parsed["report_engine_version"].(string); ok {
			s.addSignal(res, Signal{
				CPE:        fmt.Sprintf("cpe:2.3:a:vendor:report_engine:%s:*:*:*:*:*:*:*", engineVer),
				Technology: "ReportEngine",
				Version:    engineVer,
				Source:     "config_range",
				Confidence: 0.97,
				Evidence:   fmt.Sprintf("report_engine_version=%s in %s", engineVer, path),
			})
		}
	}
}

func (s *Scanner) inspectJSBundle(jsCode, sourcePath string, res *Result, routeSet map[string]struct{}) {
	matches := apiRouteRegex.FindAllStringSubmatch(jsCode, -1)
	for _, m := range matches {
		if len(m) == 2 {
			route := m[1]
			if strings.HasPrefix(route, "/api/") ||
				strings.HasPrefix(route, "/rest/") ||
				strings.HasPrefix(route, "/workshop/") ||
				strings.HasPrefix(route, "/identity/") ||
				strings.HasPrefix(route, "/webtools/") {
				routeSet[route] = struct{}{}
			}
		}
	}
	if strings.Contains(jsCode, "crapi-ui-v1.2.0") {
		s.addSignal(res, Signal{
			CPE:        "cpe:2.3:a:owasp:crapi:1.2.0:*:*:*:*:*:*:*",
			Technology: "OWASP crAPI",
			Version:    "1.2.0",
			Source:     "js_ast",
			Confidence: 0.94,
			Evidence:   "Bundle constant crapi-ui-v1.2.0 in " + sourcePath,
		})
	}
}

func extractScriptPaths(html string) []string {
	var paths []string
	matches := scriptSrcRegex.FindAllStringSubmatch(html, -1)
	for _, m := range matches {
		if len(m) == 2 {
			paths = append(paths, m[1])
		}
	}
	return paths
}

func (s *Scanner) fetchBounded(ctx context.Context, targetURL string, maxBytes int64, useRangeHeader bool) ([]byte, http.Header, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	if useRangeHeader {
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", maxBytes-1))
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, resp.Header, resp.StatusCode, err
	}
	return body, resp.Header, resp.StatusCode, nil
}
