package models

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
