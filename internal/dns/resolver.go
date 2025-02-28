package dns

import (
	"github.com/miekg/dns"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
)

// Resolver handles DNS queries
type Resolver struct {
	client *dns.Client
	server string
}

// NewResolver creates a new DNS resolver
func NewResolver() *Resolver {
	return &Resolver{
		client: new(dns.Client),
		server: "8.8.8.8:53", // Google DNS by default
	}
}

// SetServer changes the DNS server
func (r *Resolver) SetServer(server string) {
	r.server = server
}

// GetIPs gets A and AAAA records for a domain
func (r *Resolver) GetIPs(domain string) []string {
	var ips []string

	// Get A records
	aRecords, _ := r.GetDNSRecords(domain, "A")
	for _, record := range aRecords {
		if r, ok := record.(*models.GenericRecord); ok {
			ips = append(ips, r.Value)
		}
	}

	// Get AAAA records
	aaaaRecords, _ := r.GetDNSRecords(domain, "AAAA")
	for _, record := range aaaaRecords {
		if r, ok := record.(*models.GenericRecord); ok {
			ips = append(ips, r.Value)
		}
	}

	return ips
}

// GetDNSRecords gets DNS records of a specific type
func (r *Resolver) GetDNSRecords(domain string, recordType string) ([]interface{}, error) {
	var results []interface{}

	m := new(dns.Msg)

	m.SetQuestion(dns.Fqdn(domain), dns.StringToType[recordType])
	m.RecursionDesired = true

	resp, _, err := r.client.Exchange(m, r.server)
	if err != nil {
		return nil, err
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, nil
	}

	for _, answer := range resp.Answer {
		switch recordType {
		case "A", "AAAA":
			if record, ok := answer.(*dns.A); ok {
				results = append(results, &models.GenericRecord{Value: record.A.String()})
			} else if record, ok := answer.(*dns.AAAA); ok {
				results = append(results, &models.GenericRecord{Value: record.AAAA.String()})
			}
		case "MX":
			if record, ok := answer.(*dns.MX); ok {
				results = append(results, &models.MXRecord{
					Preference: int(record.Preference),
					Exchange:   record.Mx,
				})
			}
		case "SOA":
			if record, ok := answer.(*dns.SOA); ok {
				results = append(results, &models.SOARecord{
					MName:   record.Ns,
					RName:   record.Mbox,
					Serial:  record.Serial,
					Refresh: record.Refresh,
					Retry:   record.Retry,
					Expire:  record.Expire,
					Minimum: record.Minttl,
				})
			}
		case "CNAME":
			if record, ok := answer.(*dns.CNAME); ok {
				results = append(results, &models.CNAMERecord{
					Target: record.Target,
				})
			}
		case "NS":
			if record, ok := answer.(*dns.NS); ok {
				results = append(results, &models.NSRecord{
					NameServer: record.Ns,
				})
			}
		case "TXT":
			if record, ok := answer.(*dns.TXT); ok {
				results = append(results, &models.TXTRecord{
					Text: record.Txt[0],
				})
			}
		default:
			results = append(results, &models.GenericRecord{Value: answer.String()})
		}
	}

	return results, nil
}
