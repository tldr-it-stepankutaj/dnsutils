package models

// ZoneTransferResult represents the result of an AXFR attempt against a single nameserver
type ZoneTransferResult struct {
	Nameserver string   `json:"nameserver"`
	Vulnerable bool     `json:"vulnerable"`
	Records    []string `json:"records,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// DNSSECResult represents the DNSSEC validation state for a domain
type DNSSECResult struct {
	Enabled   bool     `json:"enabled"`
	Valid     bool     `json:"valid"`
	KeyTypes  []string `json:"key_types,omitempty"`
	Algorithm string   `json:"algorithm,omitempty"`
	DSRecords int      `json:"ds_records"`
	DNSKEYs   int      `json:"dnskeys"`
	Issues    []string `json:"issues,omitempty"`
}

// CacheSnoopResult represents whether a domain was found in a DNS server's cache
type CacheSnoopResult struct {
	Server string `json:"server"`
	Domain string `json:"domain"`
	Cached bool   `json:"cached"`
	TTL    uint32 `json:"ttl,omitempty"`
}
