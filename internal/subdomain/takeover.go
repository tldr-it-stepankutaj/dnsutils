package subdomain

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
)

// serviceFingerprint describes a known vulnerable service and its detection pattern
type serviceFingerprint struct {
	Service       string
	CNamePatterns []string
	Fingerprint   string
	Exploitable   bool
}

// TakeoverChecker checks subdomains for potential takeover vulnerabilities
type TakeoverChecker struct {
	fingerprints []serviceFingerprint
	httpClient   *http.Client
	dnsTimeout   time.Duration
}

// NewTakeoverChecker creates a new TakeoverChecker with built-in fingerprints
func NewTakeoverChecker() *TakeoverChecker {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return &TakeoverChecker{
		fingerprints: buildFingerprints(),
		httpClient:   client,
		dnsTimeout:   3 * time.Second,
	}
}

// buildFingerprints returns the built-in database of vulnerable service fingerprints
func buildFingerprints() []serviceFingerprint {
	return []serviceFingerprint{
		{
			Service:       "GitHub Pages",
			CNamePatterns: []string{"github.io"},
			Fingerprint:   "There isn't a GitHub Pages site here",
			Exploitable:   true,
		},
		{
			Service:       "Heroku",
			CNamePatterns: []string{"herokuapp.com", "herokussl.com"},
			Fingerprint:   "No such app",
			Exploitable:   true,
		},
		{
			Service:       "AWS S3",
			CNamePatterns: []string{"s3.amazonaws.com", "s3-website"},
			Fingerprint:   "NoSuchBucket",
			Exploitable:   true,
		},
		{
			Service:       "Shopify",
			CNamePatterns: []string{"myshopify.com"},
			Fingerprint:   "Sorry, this shop is currently unavailable",
			Exploitable:   true,
		},
		{
			Service:       "Tumblr",
			CNamePatterns: []string{"tumblr.com"},
			Fingerprint:   "There's nothing here",
			Exploitable:   true,
		},
		{
			Service:       "WordPress.com",
			CNamePatterns: []string{"wordpress.com"},
			Fingerprint:   "Do you want to register",
			Exploitable:   true,
		},
		{
			Service:       "Pantheon",
			CNamePatterns: []string{"pantheonsite.io"},
			Fingerprint:   "404 error unknown site",
			Exploitable:   true,
		},
		{
			Service:       "Fastly",
			CNamePatterns: []string{"fastly.net"},
			Fingerprint:   "Fastly error: unknown domain",
			Exploitable:   true,
		},
		{
			Service:       "Ghost",
			CNamePatterns: []string{"ghost.io"},
			Fingerprint:   "The thing you were looking for is no longer here",
			Exploitable:   true,
		},
		{
			Service:       "Surge.sh",
			CNamePatterns: []string{"surge.sh"},
			Fingerprint:   "project not found",
			Exploitable:   true,
		},
		{
			Service:       "Zendesk",
			CNamePatterns: []string{"zendesk.com"},
			Fingerprint:   "Help Center Closed",
			Exploitable:   true,
		},
		{
			Service:       "Azure Web Apps",
			CNamePatterns: []string{"azurewebsites.net"},
			Fingerprint:   "Error 404 - Web app not found",
			Exploitable:   true,
		},
		{
			Service:       "Azure Cloud Apps",
			CNamePatterns: []string{"cloudapp.net"},
			Fingerprint:   "The resource you are looking for has been removed",
			Exploitable:   true,
		},
		{
			Service:       "Azure Blob Storage",
			CNamePatterns: []string{"blob.core.windows.net"},
			Fingerprint:   "BlobNotFound",
			Exploitable:   true,
		},
		{
			Service:       "Azure API Management",
			CNamePatterns: []string{"azure-api.net"},
			Fingerprint:   "The service is unavailable",
			Exploitable:   true,
		},
		{
			Service:       "Azure Front Door",
			CNamePatterns: []string{"azurefd.net"},
			Fingerprint:   "Our services aren't available right now",
			Exploitable:   true,
		},
		{
			Service:       "Azure Traffic Manager",
			CNamePatterns: []string{"trafficmanager.net"},
			Fingerprint:   "page could not be displayed",
			Exploitable:   true,
		},
		{
			Service:       "Unbounce",
			CNamePatterns: []string{"unbouncepages.com"},
			Fingerprint:   "The requested URL was not found",
			Exploitable:   true,
		},
		{
			Service:       "Cargo",
			CNamePatterns: []string{"cargocollective.com"},
			Fingerprint:   "404 Not Found",
			Exploitable:   true,
		},
		{
			Service:       "Fly.io",
			CNamePatterns: []string{"fly.dev"},
			Fingerprint:   "404 Not Found",
			Exploitable:   true,
		},
	}
}

// CheckSubdomains checks a list of subdomains for potential takeover vulnerabilities
func (tc *TakeoverChecker) CheckSubdomains(subdomains []models.SubdomainInfo, dnsServer string) []models.TakeoverResult {
	var results []models.TakeoverResult

	if dnsServer == "" {
		dnsServer = "8.8.8.8:53"
	} else if !strings.Contains(dnsServer, ":") {
		dnsServer = dnsServer + ":53"
	}

	for _, sub := range subdomains {
		cname, err := tc.resolveCNAME(sub.Name, dnsServer)
		if err != nil || cname == "" {
			continue
		}

		fp := tc.matchFingerprint(cname)
		if fp == nil {
			continue
		}

		result := models.TakeoverResult{
			Subdomain: sub.Name,
			CNAME:     cname,
			Service:   fp.Service,
			Risk:      "Low",
		}

		vulnerable := tc.checkHTTPFingerprint(sub.Name, fp.Fingerprint)
		if vulnerable && fp.Exploitable {
			result.Vulnerable = true
			result.Fingerprint = fp.Fingerprint
			result.Risk = "High"
		} else if vulnerable {
			result.Vulnerable = false
			result.Fingerprint = fp.Fingerprint
			result.Risk = "Medium"
		}

		results = append(results, result)
	}

	return results
}

// resolveCNAME resolves the CNAME record for the given domain using the specified DNS server
func (tc *TakeoverChecker) resolveCNAME(domain string, dnsServer string) (string, error) {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	msg := new(dns.Msg)
	msg.SetQuestion(domain, dns.TypeCNAME)
	msg.RecursionDesired = true

	client := &dns.Client{
		Timeout: tc.dnsTimeout,
	}

	resp, _, err := client.Exchange(msg, dnsServer)
	if err != nil {
		return "", fmt.Errorf("dns query failed for %s: %w", domain, err)
	}

	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return "", nil
	}

	for _, answer := range resp.Answer {
		if cname, ok := answer.(*dns.CNAME); ok {
			return strings.TrimSuffix(cname.Target, "."), nil
		}
	}

	return "", nil
}

// matchFingerprint checks if a CNAME matches any known vulnerable service
func (tc *TakeoverChecker) matchFingerprint(cname string) *serviceFingerprint {
	cnameLower := strings.ToLower(cname)
	for i := range tc.fingerprints {
		for _, pattern := range tc.fingerprints[i].CNamePatterns {
			if strings.Contains(cnameLower, strings.ToLower(pattern)) {
				return &tc.fingerprints[i]
			}
		}
	}
	return nil
}

// checkHTTPFingerprint performs an HTTP GET request and checks the response body
// for the given fingerprint string
func (tc *TakeoverChecker) checkHTTPFingerprint(subdomain string, fingerprint string) bool {
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, subdomain)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; dnsutils/1.0)")

		resp, err := tc.httpClient.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // limit to 1 MB
		resp.Body.Close()
		if err != nil {
			continue
		}

		if strings.Contains(string(body), fingerprint) {
			return true
		}
	}

	return false
}
