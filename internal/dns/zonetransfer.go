package dns

import (
	"fmt"
	"strings"

	mdns "github.com/miekg/dns"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
)

// TestZoneTransfer tests AXFR against all nameservers for a domain.
// It first resolves the NS records for the domain, then attempts a full
// zone transfer against each nameserver. A successful transfer indicates
// the nameserver is vulnerable to unauthorized zone transfers.
func (r *Resolver) TestZoneTransfer(domain string) []models.ZoneTransferResult {
	domain = mdns.Fqdn(domain)

	// Step 1: Get NS records for the domain
	nameservers, err := r.getNameservers(domain)
	if err != nil || len(nameservers) == 0 {
		return []models.ZoneTransferResult{
			{
				Nameserver: "",
				Vulnerable: false,
				Error:      fmt.Sprintf("failed to resolve NS records for %s: %v", domain, err),
			},
		}
	}

	// Step 2: Attempt AXFR against each nameserver
	var results []models.ZoneTransferResult
	for _, ns := range nameservers {
		result := r.attemptAXFR(domain, ns)
		results = append(results, result)
	}

	return results
}

// getNameservers resolves NS records for the given domain
func (r *Resolver) getNameservers(domain string) ([]string, error) {
	msg := new(mdns.Msg)
	msg.SetQuestion(domain, mdns.TypeNS)
	msg.RecursionDesired = true

	resp, _, err := r.client.Exchange(msg, r.server)
	if err != nil {
		return nil, fmt.Errorf("NS query failed: %w", err)
	}

	if resp.Rcode != mdns.RcodeSuccess {
		return nil, fmt.Errorf("NS query returned rcode %s", mdns.RcodeToString[resp.Rcode])
	}

	var nameservers []string
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*mdns.NS); ok {
			nameservers = append(nameservers, ns.Ns)
		}
	}

	return nameservers, nil
}

// attemptAXFR tries a zone transfer against a single nameserver
func (r *Resolver) attemptAXFR(domain, nameserver string) models.ZoneTransferResult {
	result := models.ZoneTransferResult{
		Nameserver: nameserver,
	}

	// Ensure the nameserver has a port
	target := nameserver
	if !strings.Contains(target, ":") {
		target = target + ":53"
	}

	// Build the AXFR message
	msg := new(mdns.Msg)
	msg.SetAxfr(domain)

	transfer := new(mdns.Transfer)
	channel, err := transfer.In(msg, target)
	if err != nil {
		result.Error = fmt.Sprintf("transfer initiation failed: %v", err)
		return result
	}

	// Read all envelopes from the transfer
	var records []string
	for envelope := range channel {
		if envelope.Error != nil {
			result.Error = fmt.Sprintf("transfer error: %v", envelope.Error)
			// If we already collected some records, the server was still vulnerable
			if len(records) > 0 {
				result.Vulnerable = true
				result.Records = records
			}
			return result
		}
		for _, rr := range envelope.RR {
			records = append(records, rr.String())
		}
	}

	if len(records) > 0 {
		result.Vulnerable = true
		result.Records = records
	}

	return result
}
