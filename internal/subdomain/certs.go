package subdomain

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// CertFinder handles subdomain discovery via certificates
type CertFinder struct {
	Client *http.Client
}

// NewCertFinder creates a new certificate-based subdomain finder
func NewCertFinder() *CertFinder {
	return &CertFinder{
		Client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// CertEntry represents an entry from certificate transparency logs
type CertEntry struct {
	NameValue string `json:"name_value"`
}

// FindSubdomainsFromCertificates finds subdomains using CT logs
func (cf *CertFinder) FindSubdomainsFromCertificates(domain string) []string {
	subdomains := make(map[string]struct{})

	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	resp, err := cf.Client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	var entries []CertEntry
	err = json.NewDecoder(resp.Body).Decode(&entries)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		name := strings.ToLower(entry.NameValue)

		// Handle wildcard entries
		if strings.HasPrefix(name, "*.") {
			name = name[2:]
		}

		// Make sure it's a subdomain and not the domain itself
		if strings.Contains(name, domain) && name != domain {
			subdomains[name] = struct{}{}
		}
	}

	// Convert map to slice
	var result []string
	for subdomain := range subdomains {
		result = append(result, subdomain)
	}

	return result
}

// CheckSubdomain checks if a subdomain exists and gets its IP
func (cf *CertFinder) CheckSubdomain(subdomain string) (string, string, error) {
	ips, err := net.LookupHost(subdomain)
	if err != nil {
		return "", "", err
	}

	if len(ips) > 0 {
		return subdomain, ips[0], nil
	}

	return "", "", fmt.Errorf("no IP addresses found")
}
