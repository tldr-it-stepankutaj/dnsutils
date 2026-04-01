package subdomain

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// PassiveFinder discovers subdomains using passive online sources
type PassiveFinder struct {
	Client *http.Client
}

// NewPassiveFinder creates a new passive subdomain finder
func NewPassiveFinder() *PassiveFinder {
	return &PassiveFinder{
		Client: &http.Client{Timeout: 30 * time.Second},
	}
}

// FindSubdomains queries multiple passive sources concurrently and merges results
func (pf *PassiveFinder) FindSubdomains(domain string) []string {
	var mu sync.Mutex
	seen := make(map[string]struct{})

	sources := []struct {
		name string
		fn   func(string) []string
	}{
		{"HackerTarget", pf.queryHackerTarget},
		{"AlienVault OTX", pf.queryAlienVaultOTX},
		{"URLScan.io", pf.queryURLScan},
		{"Wayback Machine", pf.queryWaybackMachine},
		{"RapidDNS", pf.queryRapidDNS},
	}

	var wg sync.WaitGroup
	for _, src := range sources {
		wg.Add(1)
		go func(name string, fn func(string) []string) {
			defer wg.Done()
			results := fn(domain)
			mu.Lock()
			for _, sub := range results {
				sub = strings.ToLower(strings.TrimSpace(sub))
				if sub != "" && isSubdomainOf(sub, domain) {
					seen[sub] = struct{}{}
				}
			}
			mu.Unlock()
			log.Printf("[passive] %s returned %d results for %s", name, len(results), domain)
		}(src.name, src.fn)
	}
	wg.Wait()

	results := make([]string, 0, len(seen))
	for sub := range seen {
		results = append(results, sub)
	}
	return results
}

// isSubdomainOf checks whether candidate is a subdomain of domain
func isSubdomainOf(candidate, domain string) bool {
	candidate = strings.TrimSuffix(candidate, ".")
	domain = strings.TrimSuffix(domain, ".")
	if candidate == domain {
		return true
	}
	return strings.HasSuffix(candidate, "."+domain)
}

// queryHackerTarget queries the HackerTarget host search API
func (pf *PassiveFinder) queryHackerTarget(domain string) []string {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	body, err := pf.httpGet(url)
	if err != nil {
		log.Printf("[passive] HackerTarget error: %v", err)
		return nil
	}

	var results []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		if len(parts) >= 1 && parts[0] != "" {
			results = append(results, parts[0])
		}
	}
	return results
}

// queryAlienVaultOTX queries the AlienVault OTX passive DNS API
func (pf *PassiveFinder) queryAlienVaultOTX(domain string) []string {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	body, err := pf.httpGet(url)
	if err != nil {
		log.Printf("[passive] AlienVault OTX error: %v", err)
		return nil
	}

	var resp struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		log.Printf("[passive] AlienVault OTX JSON parse error: %v", err)
		return nil
	}

	var results []string
	for _, entry := range resp.PassiveDNS {
		if entry.Hostname != "" {
			results = append(results, entry.Hostname)
		}
	}
	return results
}

// queryURLScan queries the URLScan.io search API
func (pf *PassiveFinder) queryURLScan(domain string) []string {
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=100", domain)
	body, err := pf.httpGet(url)
	if err != nil {
		log.Printf("[passive] URLScan.io error: %v", err)
		return nil
	}

	var resp struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		log.Printf("[passive] URLScan.io JSON parse error: %v", err)
		return nil
	}

	var results []string
	for _, r := range resp.Results {
		if r.Page.Domain != "" {
			results = append(results, r.Page.Domain)
		}
	}
	return results
}

// queryWaybackMachine queries the Wayback Machine CDX API for archived URLs
func (pf *PassiveFinder) queryWaybackMachine(domain string) []string {
	url := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey&limit=500", domain)
	body, err := pf.httpGet(url)
	if err != nil {
		log.Printf("[passive] Wayback Machine error: %v", err)
		return nil
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		log.Printf("[passive] Wayback Machine JSON parse error: %v", err)
		return nil
	}

	seen := make(map[string]struct{})
	var results []string
	// First row is typically the header
	for i, row := range rows {
		if i == 0 || len(row) == 0 {
			continue
		}
		sub := extractDomainFromURL(row[0])
		if sub != "" {
			if _, ok := seen[sub]; !ok {
				seen[sub] = struct{}{}
				results = append(results, sub)
			}
		}
	}
	return results
}

// queryRapidDNS queries the RapidDNS HTML page and extracts subdomains via regex
func (pf *PassiveFinder) queryRapidDNS(domain string) []string {
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)
	body, err := pf.httpGet(url)
	if err != nil {
		log.Printf("[passive] RapidDNS error: %v", err)
		return nil
	}

	// Match subdomains in table cells: patterns like "something.domain.tld"
	pattern := fmt.Sprintf(`(?i)([a-zA-Z0-9][-a-zA-Z0-9]*\.)*%s`, regexp.QuoteMeta(domain))
	re := regexp.MustCompile(pattern)
	matches := re.FindAllString(string(body), -1)

	seen := make(map[string]struct{})
	var results []string
	for _, m := range matches {
		m = strings.ToLower(m)
		if _, ok := seen[m]; !ok {
			seen[m] = struct{}{}
			results = append(results, m)
		}
	}
	return results
}

// httpGet performs a GET request and returns the response body
func (pf *PassiveFinder) httpGet(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", "dnsutils/1.0")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	resp, err := pf.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP GET %s returned status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	return body, nil
}

// extractDomainFromURL extracts the hostname from a URL string
func extractDomainFromURL(rawURL string) string {
	// Remove protocol
	u := rawURL
	if idx := strings.Index(u, "://"); idx != -1 {
		u = u[idx+3:]
	}
	// Remove path
	if idx := strings.Index(u, "/"); idx != -1 {
		u = u[:idx]
	}
	// Remove port
	if idx := strings.Index(u, ":"); idx != -1 {
		u = u[:idx]
	}
	return strings.TrimSpace(u)
}
