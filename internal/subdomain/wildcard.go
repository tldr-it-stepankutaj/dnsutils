package subdomain

import (
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"time"
)

// WildcardDetector detects wildcard DNS configurations
type WildcardDetector struct{}

// NewWildcardDetector creates a new wildcard detector
func NewWildcardDetector() *WildcardDetector {
	return &WildcardDetector{}
}

// WildcardResult contains the outcome of a wildcard DNS check
type WildcardResult struct {
	IsWildcard bool     `json:"is_wildcard"`
	WildcardIP []string `json:"wildcard_ips,omitempty"`
}

// DetectWildcard checks if a domain has wildcard DNS configured
// by resolving random non-existent subdomains and comparing results
func (wd *WildcardDetector) DetectWildcard(domain string) *WildcardResult {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	const numProbes = 3
	var allIPs [][]string

	for i := 0; i < numProbes; i++ {
		randomSub := randomString(rng, 12)
		fqdn := fmt.Sprintf("%s.%s", randomSub, domain)

		addrs, err := net.LookupHost(fqdn)
		if err != nil {
			// If any random subdomain fails to resolve, it's not a wildcard
			return &WildcardResult{IsWildcard: false}
		}
		sort.Strings(addrs)
		allIPs = append(allIPs, addrs)
	}

	// Check if all probes resolved to the same set of IPs
	if len(allIPs) < numProbes {
		return &WildcardResult{IsWildcard: false}
	}

	baseline := strings.Join(allIPs[0], ",")
	for i := 1; i < numProbes; i++ {
		if strings.Join(allIPs[i], ",") != baseline {
			return &WildcardResult{IsWildcard: false}
		}
	}

	return &WildcardResult{
		IsWildcard: true,
		WildcardIP: allIPs[0],
	}
}

// randomString generates a random lowercase alphanumeric string of the given length
func randomString(rng *rand.Rand, length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rng.Intn(len(charset))]
	}
	return string(b)
}
