package models

// Results represents the complete scan results
type Results struct {
	Domain           string                      `json:"domain"`
	DomainIPs        []string                    `json:"domain_ips"`
	Records          map[string]interface{}      `json:"records"`
	Subdomains       []SubdomainInfo             `json:"subdomains"`
	SubdomainData    map[string]SubdomainDetails `json:"subdomain_data"`
	CertSubdomains   []string                    `json:"cert_subdomains"`
	BruteSubdomains  []string                    `json:"brute_subdomains"`
	SecurityAnalysis *SecurityResult             `json:"security_analysis,omitempty"`
	CloudAnalysis    *CloudAnalysisResult        `json:"cloud_analysis,omitempty"`
}

// SubdomainInfo represents basic subdomain information
type SubdomainInfo struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

// SubdomainDetails represents detailed information about a subdomain
type SubdomainDetails struct {
	IP           string   `json:"ip"`
	ASN          string   `json:"asn"`
	OpenServices []string `json:"open_services"`
	SSLInfo      *SSLInfo `json:"ssl_info,omitempty"`
}

// SSLInfo represents SSL certificate information
type SSLInfo struct {
	CommonName string `json:"common_name"`
	Issuer     string `json:"issuer"`
	Expiry     string `json:"expiry"`
}

// MXRecord represents an MX record
type MXRecord struct {
	Preference int    `json:"preference"`
	Exchange   string `json:"exchange"`
}

// SOARecord represents an SOA record
type SOARecord struct {
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
}

// CNAMERecord represents a CNAME record
type CNAMERecord struct {
	Target string `json:"target"`
}

// NSRecord represents an NS record
type NSRecord struct {
	NameServer string `json:"nameserver"`
}

// TXTRecord represents a TXT record
type TXTRecord struct {
	Text string `json:"text"`
}

// GenericRecord represents a generic DNS record
type GenericRecord struct {
	Value string `json:"value"`
}

// PortScanOptions contains options for port scanning
type PortScanOptions struct {
	Ports         []int
	Timeout       int
	MaxConcurrent int
}
