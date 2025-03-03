package models

// Results represents the complete scan results
type Results struct {
	Domain          string                      `json:"domain"`
	DomainIPs       []string                    `json:"domain_ips"`
	Records         map[string]interface{}      `json:"records"`
	Subdomains      []SubdomainInfo             `json:"subdomains"`
	SubdomainData   map[string]SubdomainDetails `json:"subdomain_data"`
	CertSubdomains  []string                    `json:"cert_subdomains"`
	BruteSubdomains []string                    `json:"brute_subdomains"`
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

// SecurityResult represents the results of a security configuration analysis
type SecurityResult struct {
	SPFRecord       *SPFAnalysis    `json:"spf_record,omitempty"`
	DMARCRecord     *DMARCAnalysis  `json:"dmarc_record,omitempty"`
	DKIMRecords     []*DKIMAnalysis `json:"dkim_records,omitempty"`
	MXAnalysis      *MXAnalysis     `json:"mx_analysis,omitempty"`
	CAAAnalysis     *CAAAnalysis    `json:"caa_analysis,omitempty"`
	SecurityScore   int             `json:"security_score"`
	Recommendations []string        `json:"recommendations"`
}

// SPFAnalysis represents analysis of SPF record
type SPFAnalysis struct {
	Record         string   `json:"record"`
	Valid          bool     `json:"valid"`
	Policy         string   `json:"policy"`
	Includes       []string `json:"includes,omitempty"`
	IPAddresses    []string `json:"ip_addresses,omitempty"`
	HasRedirect    bool     `json:"has_redirect"`
	RedirectDomain string   `json:"redirect_domain,omitempty"`
	Issues         []string `json:"issues,omitempty"`
}

// DMARCAnalysis represents analysis of DMARC record
type DMARCAnalysis struct {
	Record          string   `json:"record"`
	Valid           bool     `json:"valid"`
	Policy          string   `json:"policy"`
	SubdomainPolicy string   `json:"subdomain_policy,omitempty"`
	Percentage      int      `json:"percentage"`
	ReportURI       []string `json:"report_uri,omitempty"`
	ForensicURI     []string `json:"forensic_uri,omitempty"`
	Issues          []string `json:"issues,omitempty"`
}

// DKIMAnalysis represents analysis of DKIM record
type DKIMAnalysis struct {
	Selector  string   `json:"selector"`
	Record    string   `json:"record"`
	Valid     bool     `json:"valid"`
	PublicKey string   `json:"public_key,omitempty"`
	KeyType   string   `json:"key_type,omitempty"`
	Issues    []string `json:"issues,omitempty"`
}

// MXAnalysis represents analysis of MX records
type MXAnalysis struct {
	Servers       []string `json:"servers"`
	HasBackup     bool     `json:"has_backup"`
	AllSecure     bool     `json:"all_secure"`
	SecureServers []string `json:"secure_servers,omitempty"`
	Issues        []string `json:"issues,omitempty"`
}

// CAAAnalysis represents analysis of CAA records
type CAAAnalysis struct {
	Records          []string `json:"records"`
	HasIssueWildcard bool     `json:"has_issue_wildcard"`
	IssueCAs         []string `json:"issue_cas,omitempty"`
	IssueWildcardCAs []string `json:"issue_wildcard_cas,omitempty"`
	HasIODEF         bool     `json:"has_iodef"`
	IODEFURIs        []string `json:"iodef_uris,omitempty"`
	Issues           []string `json:"issues,omitempty"`
}
