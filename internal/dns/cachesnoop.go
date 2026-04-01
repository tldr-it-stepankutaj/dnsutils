package dns

import (
	"strings"

	mdns "github.com/miekg/dns"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
)

// CacheSnoop performs DNS cache snooping on a target DNS server.
// It sends non-recursive queries (RD=0) for each domain to check whether
// the records are already present in the server's cache. A cached record
// indicates that someone recently queried that domain through the target server.
func (r *Resolver) CacheSnoop(targetServer string, domains []string) []models.CacheSnoopResult {
	// Ensure the target server has a port
	if !strings.Contains(targetServer, ":") {
		targetServer = targetServer + ":53"
	}

	var results []models.CacheSnoopResult

	for _, domain := range domains {
		result := r.snoopDomain(targetServer, domain)
		results = append(results, result)
	}

	return results
}

// snoopDomain sends a non-recursive query for a single domain to check the cache
func (r *Resolver) snoopDomain(targetServer, domain string) models.CacheSnoopResult {
	domain = mdns.Fqdn(domain)

	result := models.CacheSnoopResult{
		Server: targetServer,
		Domain: domain,
	}

	msg := new(mdns.Msg)
	msg.SetQuestion(domain, mdns.TypeA)
	msg.RecursionDesired = false // RD=0: non-recursive query for cache snooping

	resp, _, err := r.client.Exchange(msg, targetServer)
	if err != nil {
		// Not cached or server refused — treat as not cached
		return result
	}

	if resp.Rcode != mdns.RcodeSuccess {
		return result
	}

	// If we got answer records, the domain was in the cache
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == mdns.TypeA || rr.Header().Rrtype == mdns.TypeAAAA || rr.Header().Rrtype == mdns.TypeCNAME {
			result.Cached = true
			result.TTL = rr.Header().Ttl
			break
		}
	}

	// If no A/AAAA/CNAME but we still got an answer, check generically
	if !result.Cached && len(resp.Answer) > 0 {
		result.Cached = true
		result.TTL = resp.Answer[0].Header().Ttl
	}

	return result
}
