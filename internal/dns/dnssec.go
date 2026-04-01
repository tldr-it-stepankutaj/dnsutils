package dns

import (
	"fmt"

	mdns "github.com/miekg/dns"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
)

// CheckDNSSEC validates DNSSEC configuration for a domain.
// It checks for DNSKEY records, DS records in the parent zone,
// and RRSIG signatures to determine whether DNSSEC is enabled
// and properly configured.
func (r *Resolver) CheckDNSSEC(domain string) *models.DNSSECResult {
	domain = mdns.Fqdn(domain)

	result := &models.DNSSECResult{}

	// Step 1: Query DNSKEY records
	dnskeys, err := r.queryDNSKEY(domain)
	if err != nil {
		result.Issues = append(result.Issues, fmt.Sprintf("DNSKEY query failed: %v", err))
		return result
	}
	result.DNSKEYs = len(dnskeys)

	// Step 2: Query DS records from parent zone
	dsRecords, err := r.queryDS(domain)
	if err != nil {
		result.Issues = append(result.Issues, fmt.Sprintf("DS query failed: %v", err))
	}
	result.DSRecords = len(dsRecords)

	// Step 3: Check RRSIG records via EDNS0 with DO bit
	hasRRSIG, err := r.checkRRSIG(domain)
	if err != nil {
		result.Issues = append(result.Issues, fmt.Sprintf("RRSIG check failed: %v", err))
	}

	// Determine if DNSSEC is enabled
	if len(dnskeys) > 0 || len(dsRecords) > 0 {
		result.Enabled = true
	}

	// Extract key types and algorithm from DNSKEY records
	keyTypeSet := make(map[string]bool)
	for _, key := range dnskeys {
		switch key.Flags {
		case 256:
			keyTypeSet["ZSK"] = true
		case 257:
			keyTypeSet["KSK"] = true
		default:
			keyTypeSet[fmt.Sprintf("flags=%d", key.Flags)] = true
		}
		if result.Algorithm == "" {
			result.Algorithm = mdns.AlgorithmToString[key.Algorithm]
		}
	}
	for kt := range keyTypeSet {
		result.KeyTypes = append(result.KeyTypes, kt)
	}

	// Step 4: Validate the chain
	if result.Enabled {
		result.Valid = r.validateChain(dnskeys, dsRecords, hasRRSIG, result)
	}

	return result
}

// queryDNSKEY retrieves DNSKEY records for the domain
func (r *Resolver) queryDNSKEY(domain string) ([]*mdns.DNSKEY, error) {
	msg := new(mdns.Msg)
	msg.SetQuestion(domain, mdns.TypeDNSKEY)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, true) // Enable DNSSEC OK (DO) bit

	resp, _, err := r.client.Exchange(msg, r.server)
	if err != nil {
		return nil, err
	}

	if resp.Rcode != mdns.RcodeSuccess {
		return nil, fmt.Errorf("DNSKEY query returned rcode %s", mdns.RcodeToString[resp.Rcode])
	}

	var keys []*mdns.DNSKEY
	for _, rr := range resp.Answer {
		if key, ok := rr.(*mdns.DNSKEY); ok {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// queryDS retrieves DS records for the domain from the parent zone
func (r *Resolver) queryDS(domain string) ([]*mdns.DS, error) {
	msg := new(mdns.Msg)
	msg.SetQuestion(domain, mdns.TypeDS)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, true)

	resp, _, err := r.client.Exchange(msg, r.server)
	if err != nil {
		return nil, err
	}

	if resp.Rcode != mdns.RcodeSuccess {
		return nil, fmt.Errorf("DS query returned rcode %s", mdns.RcodeToString[resp.Rcode])
	}

	var dsRecords []*mdns.DS
	for _, rr := range resp.Answer {
		if ds, ok := rr.(*mdns.DS); ok {
			dsRecords = append(dsRecords, ds)
		}
	}

	return dsRecords, nil
}

// checkRRSIG sends a query with the DO bit set and checks for RRSIG records
func (r *Resolver) checkRRSIG(domain string) (bool, error) {
	msg := new(mdns.Msg)
	msg.SetQuestion(domain, mdns.TypeA)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, true) // DO bit enables DNSSEC responses

	resp, _, err := r.client.Exchange(msg, r.server)
	if err != nil {
		return false, err
	}

	// Look for RRSIG in the answer section
	for _, rr := range resp.Answer {
		if _, ok := rr.(*mdns.RRSIG); ok {
			return true, nil
		}
	}

	return false, nil
}

// validateChain checks the DNSSEC trust chain integrity
func (r *Resolver) validateChain(dnskeys []*mdns.DNSKEY, dsRecords []*mdns.DS, hasRRSIG bool, result *models.DNSSECResult) bool {
	valid := true

	// Check that we have both KSK and ZSK
	hasKSK := false
	hasZSK := false
	for _, key := range dnskeys {
		if key.Flags == 257 {
			hasKSK = true
		}
		if key.Flags == 256 {
			hasZSK = true
		}
	}

	if !hasKSK {
		result.Issues = append(result.Issues, "no KSK (Key Signing Key) found")
		valid = false
	}
	if !hasZSK {
		result.Issues = append(result.Issues, "no ZSK (Zone Signing Key) found")
		valid = false
	}

	// Check DS records exist in parent zone
	if len(dsRecords) == 0 {
		result.Issues = append(result.Issues, "no DS records found in parent zone - chain of trust is broken")
		valid = false
	}

	// Verify DS records match a DNSKEY
	if len(dsRecords) > 0 && len(dnskeys) > 0 {
		matched := false
		for _, ds := range dsRecords {
			for _, key := range dnskeys {
				computedDS := key.ToDS(ds.DigestType)
				if computedDS != nil && computedDS.Digest == ds.Digest {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			result.Issues = append(result.Issues, "DS record does not match any DNSKEY - chain of trust validation failed")
			valid = false
		}
	}

	// Check for RRSIG records
	if !hasRRSIG {
		result.Issues = append(result.Issues, "no RRSIG records found - zone may not be signed")
		valid = false
	}

	return valid
}
