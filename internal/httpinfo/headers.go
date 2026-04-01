package httpinfo

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
)

// securityHeaders lists the HTTP security headers to check
var securityHeaders = []string{
	"Strict-Transport-Security",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Content-Security-Policy",
	"X-XSS-Protection",
	"Referrer-Policy",
	"Permissions-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Resource-Policy",
}

// technologyHeaders maps header names to their description labels for tech detection
var technologyHeaders = []struct {
	Header string
	Label  string
}{
	{"Server", "Server"},
	{"X-Powered-By", "Powered-By"},
	{"X-AspNet-Version", "ASP.NET Version"},
	{"X-AspNetMvc-Version", "ASP.NET MVC Version"},
	{"X-Generator", "Generator"},
	{"X-Drupal-Cache", "Drupal Cache"},
	{"X-Varnish", "Varnish"},
	{"X-Cache", "Cache"},
	{"Via", "Via"},
}

// Analyzer performs HTTP header security analysis
type Analyzer struct {
	Timeout time.Duration
}

// NewAnalyzer creates a new Analyzer with default settings
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		Timeout: 10 * time.Second,
	}
}

// AnalyzeURL performs HTTP header analysis on a host.
// It tries HTTPS first, falling back to HTTP if HTTPS fails.
func (a *Analyzer) AnalyzeURL(host string) *models.HeaderAnalysis {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimRight(host, "/")

	// Try HTTPS first
	result := a.fetch("https://" + host)
	if result != nil {
		return result
	}

	// Fallback to HTTP
	return a.fetch("http://" + host)
}

// fetch performs the actual HTTP request and header analysis
func (a *Analyzer) fetch(url string) *models.HeaderAnalysis {
	client := &http.Client{
		Timeout: a.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "dnsutils/1.0 (Security Header Analyzer)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Read body for technology detection (limit to 512KB)
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	body := string(bodyBytes)

	analysis := &models.HeaderAnalysis{
		URL:             url,
		StatusCode:      resp.StatusCode,
		SecurityHeaders: make(map[string]string),
	}

	// Extract Server and X-Powered-By
	if server := resp.Header.Get("Server"); server != "" {
		analysis.Server = server
	}
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		analysis.PoweredBy = poweredBy
	}

	// Check security headers
	for _, header := range securityHeaders {
		value := resp.Header.Get(header)
		if value != "" {
			analysis.SecurityHeaders[header] = value
		} else {
			analysis.MissingHeaders = append(analysis.MissingHeaders, header)
		}
	}

	// Extract technology hints from headers
	var techHints []string
	for _, th := range technologyHeaders {
		if value := resp.Header.Get(th.Header); value != "" {
			techHints = append(techHints, fmt.Sprintf("%s: %s", th.Label, value))
		}
	}

	// Run signature-based technology detection
	detected := DetectTechnologies(resp, body)
	analysis.Technologies = append(techHints, detected...)

	// Generate findings
	analysis.Findings = generateFindings(analysis, resp)

	return analysis
}

// generateFindings produces human-readable security findings
func generateFindings(analysis *models.HeaderAnalysis, resp *http.Response) []string {
	var findings []string

	// Missing security headers
	for _, header := range analysis.MissingHeaders {
		switch header {
		case "Strict-Transport-Security":
			findings = append(findings, "HSTS not set: the site does not enforce HTTPS via Strict-Transport-Security")
		case "Content-Security-Policy":
			findings = append(findings, "No Content-Security-Policy header: the site may be vulnerable to XSS and data injection attacks")
		case "X-Frame-Options":
			findings = append(findings, "X-Frame-Options not set: the site may be vulnerable to clickjacking")
		case "X-Content-Type-Options":
			findings = append(findings, "X-Content-Type-Options not set: browsers may MIME-sniff responses")
		case "Referrer-Policy":
			findings = append(findings, "No Referrer-Policy: referrer information may leak to third parties")
		case "Permissions-Policy":
			findings = append(findings, "No Permissions-Policy header: browser features are not explicitly restricted")
		case "Cross-Origin-Opener-Policy":
			findings = append(findings, "No Cross-Origin-Opener-Policy: the site may be susceptible to cross-origin attacks")
		case "Cross-Origin-Resource-Policy":
			findings = append(findings, "No Cross-Origin-Resource-Policy: resources may be loaded by cross-origin pages")
		case "X-XSS-Protection":
			findings = append(findings, "X-XSS-Protection not set: legacy XSS filter not enabled for older browsers")
		}
	}

	// Information disclosure findings
	if analysis.Server != "" {
		findings = append(findings, fmt.Sprintf("Server header discloses technology: %s", analysis.Server))
	}
	if analysis.PoweredBy != "" {
		findings = append(findings, fmt.Sprintf("X-Powered-By header discloses technology: %s", analysis.PoweredBy))
	}
	if v := resp.Header.Get("X-AspNet-Version"); v != "" {
		findings = append(findings, fmt.Sprintf("X-AspNet-Version header discloses version: %s", v))
	}
	if v := resp.Header.Get("X-AspNetMvc-Version"); v != "" {
		findings = append(findings, fmt.Sprintf("X-AspNetMvc-Version header discloses version: %s", v))
	}
	if v := resp.Header.Get("X-Generator"); v != "" {
		findings = append(findings, fmt.Sprintf("X-Generator header discloses technology: %s", v))
	}

	return findings
}

// AnalyzeSubdomains runs header analysis for a list of subdomains concurrently.
// The concurrency parameter controls how many analyses run in parallel.
func (a *Analyzer) AnalyzeSubdomains(subdomains []models.SubdomainInfo, concurrency int) map[string]*models.HeaderAnalysis {
	if concurrency <= 0 {
		concurrency = 10
	}

	results := make(map[string]*models.HeaderAnalysis)
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, sub := range subdomains {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			analysis := a.AnalyzeURL(host)
			if analysis != nil {
				mu.Lock()
				results[host] = analysis
				mu.Unlock()
			}
		}(sub.Name)
	}

	wg.Wait()
	return results
}
