package security

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
	"regexp"
	"strings"
)

// Analyzer handles security configuration analysis
type Analyzer struct {
	Resolver *dns.Client
	Server   string
}

// NewAnalyzer creates a new security analyzer
func NewAnalyzer(server string) *Analyzer {
	return &Analyzer{
		Resolver: new(dns.Client),
		Server:   server,
	}
}

// AnalyzeDomain performs security analysis on a domain
func (a *Analyzer) AnalyzeDomain(domain string) (*SecurityResult, error) {
	result := &SecurityResult{
		SecurityScore:   0,
		Recommendations: []string{},
	}

	// Analyze SPF
	spfResult, err := a.AnalyzeSPF(domain)
	if err == nil && spfResult != nil {
		result.SPFRecord = spfResult
		if spfResult.Valid {
			result.SecurityScore += 10
		}
		for _, issue := range spfResult.Issues {
			result.Recommendations = append(result.Recommendations, fmt.Sprintf("SPF: %s", issue))
		}
	} else if err != nil {
		result.Recommendations = append(result.Recommendations, "SPF: No SPF record found. Consider adding an SPF record to prevent email spoofing.")
	}

	// Analyze DMARC
	dmarcResult, err := a.AnalyzeDMARC(domain)
	if err == nil && dmarcResult != nil {
		result.DMARCRecord = dmarcResult
		if dmarcResult.Valid {
			result.SecurityScore += 10

			// Check DMARC policy strength
			switch dmarcResult.Policy {
			case "reject":
				result.SecurityScore += 10
			case "quarantine":
				result.SecurityScore += 5
			}
		}
		for _, issue := range dmarcResult.Issues {
			result.Recommendations = append(result.Recommendations, fmt.Sprintf("DMARC: %s", issue))
		}
	} else if err != nil {
		result.Recommendations = append(result.Recommendations, "DMARC: No DMARC record found. Consider adding a DMARC record for better email security.")
	}

	// Analyze DKIM
	dkimResults, err := a.AnalyzeDKIM(domain)
	if err == nil && len(dkimResults) > 0 {
		result.DKIMRecords = dkimResults
		validCount := 0
		for _, dkim := range dkimResults {
			if dkim.Valid {
				validCount++
			}
			for _, issue := range dkim.Issues {
				result.Recommendations = append(result.Recommendations, fmt.Sprintf("DKIM (%s): %s", dkim.Selector, issue))
			}
		}
		if validCount > 0 {
			result.SecurityScore += 10
			if validCount > 1 {
				result.SecurityScore += 5
			}
		}
	} else {
		result.Recommendations = append(result.Recommendations, "DKIM: No DKIM records found. Consider setting up DKIM signing for your email.")
	}

	// Analyze MX records
	mxResult, err := a.AnalyzeMX(domain)
	if err == nil && mxResult != nil {
		result.MXAnalysis = mxResult

		if len(mxResult.Servers) > 0 {
			if mxResult.HasBackup {
				result.SecurityScore += 5
			} else {
				result.Recommendations = append(result.Recommendations, "MX: Consider adding backup MX servers for better email availability.")
			}

			if mxResult.AllSecure {
				result.SecurityScore += 10
			} else {
				result.Recommendations = append(result.Recommendations, "MX: Not all MX servers support secure transport. Consider upgrading mail servers to support TLS.")
			}
		}

		for _, issue := range mxResult.Issues {
			result.Recommendations = append(result.Recommendations, fmt.Sprintf("MX: %s", issue))
		}
	}

	// Analyze CAA records
	caaResult, err := a.AnalyzeCAA(domain)
	if err == nil && caaResult != nil {
		result.CAAAnalysis = caaResult

		if len(caaResult.IssueCAs) > 0 {
			result.SecurityScore += 10
		}

		if caaResult.HasIODEF {
			result.SecurityScore += 5
		} else {
			result.Recommendations = append(result.Recommendations, "CAA: Consider adding iodef property to receive notifications about certificate issuance violations.")
		}

		for _, issue := range caaResult.Issues {
			result.Recommendations = append(result.Recommendations, fmt.Sprintf("CAA: %s", issue))
		}
	} else {
		result.Recommendations = append(result.Recommendations, "CAA: No CAA records found. Consider adding CAA records to restrict which CAs can issue certificates for your domain.")
	}

	return result, nil
}

// AnalyzeSPF analyzes SPF record of a domain
func (a *Analyzer) AnalyzeSPF(domain string) (*SPFAnalysis, error) {
	records, err := a.getTXTRecords(domain)
	if err != nil {
		return nil, err
	}

	var spfRecord string
	for _, record := range records {
		if strings.HasPrefix(record, "v=spf1 ") {
			spfRecord = record
			break
		}
	}

	if spfRecord == "" {
		return nil, fmt.Errorf("no SPF record found")
	}

	// Initialize SPF analysis
	analysis := &SPFAnalysis{
		Record:      spfRecord,
		Valid:       true,
		Policy:      "neutral",
		Includes:    []string{},
		IPAddresses: []string{},
		Issues:      []string{},
	}

	// Parse SPF record
	parts := strings.Fields(spfRecord)
	if !strings.HasPrefix(parts[0], "v=spf1") {
		analysis.Valid = false
		analysis.Issues = append(analysis.Issues, "SPF record does not start with 'v=spf1'")
		return analysis, nil
	}

	for _, part := range parts[1:] {
		if strings.HasPrefix(part, "include:") {
			includeDomain := strings.TrimPrefix(part, "include:")
			analysis.Includes = append(analysis.Includes, includeDomain)
		} else if strings.HasPrefix(part, "ip4:") || strings.HasPrefix(part, "ip6:") {
			ipAddr := strings.Split(part, ":")[1]
			analysis.IPAddresses = append(analysis.IPAddresses, ipAddr)
		} else if strings.HasPrefix(part, "redirect=") {
			analysis.HasRedirect = true
			analysis.RedirectDomain = strings.TrimPrefix(part, "redirect=")
		} else if part == "~all" {
			analysis.Policy = "softfail"
		} else if part == "-all" {
			analysis.Policy = "fail"
		} else if part == "?all" {
			analysis.Policy = "neutral"
		} else if part == "+all" {
			analysis.Policy = "pass"
			analysis.Valid = false
			analysis.Issues = append(analysis.Issues, "SPF policy '+all' allows any server to send email as your domain, which is insecure")
		}
	}

	// Check for issues
	if analysis.Policy == "neutral" || analysis.Policy == "pass" {
		analysis.Issues = append(analysis.Issues, "Your SPF policy is too permissive. Consider using '~all' or '-all' instead")
	}

	if len(analysis.Includes) > 10 {
		analysis.Issues = append(analysis.Issues, "Too many SPF includes (>10) which may cause lookup limits to be exceeded")
	}

	if !strings.Contains(spfRecord, "all") {
		analysis.Issues = append(analysis.Issues, "Missing terminal 'all' mechanism")
		analysis.Valid = false
	}

	return analysis, nil
}

// AnalyzeDMARC analyzes DMARC record of a domain
func (a *Analyzer) AnalyzeDMARC(domain string) (*DMARCAnalysis, error) {
	records, err := a.getTXTRecords("_dmarc." + domain)
	if err != nil {
		return nil, err
	}

	var dmarcRecord string
	for _, record := range records {
		if strings.HasPrefix(record, "v=DMARC1") {
			dmarcRecord = record
			break
		}
	}

	if dmarcRecord == "" {
		return nil, fmt.Errorf("no DMARC record found")
	}

	// Initialize DMARC analysis
	analysis := &DMARCAnalysis{
		Record:          dmarcRecord,
		Valid:           true,
		Policy:          "none",
		SubdomainPolicy: "",
		Percentage:      100,
		ReportURI:       []string{},
		ForensicURI:     []string{},
		Issues:          []string{},
	}

	// Check record format
	if !strings.HasPrefix(dmarcRecord, "v=DMARC1") {
		analysis.Valid = false
		analysis.Issues = append(analysis.Issues, "DMARC record does not start with 'v=DMARC1'")
		return analysis, nil
	}

	// Parse DMARC record
	parts := strings.Split(dmarcRecord, ";")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if i == 0 && part != "v=DMARC1" {
			analysis.Valid = false
			analysis.Issues = append(analysis.Issues, "Invalid DMARC version")
		} else if strings.HasPrefix(part, "p=") {
			policy := strings.TrimPrefix(part, "p=")
			analysis.Policy = policy
			if policy == "none" {
				analysis.Issues = append(analysis.Issues, "Policy is set to 'none' which only monitors and doesn't take action")
			}
		} else if strings.HasPrefix(part, "sp=") {
			subPolicy := strings.TrimPrefix(part, "sp=")
			analysis.SubdomainPolicy = subPolicy
		} else if strings.HasPrefix(part, "pct=") {
			pct := strings.TrimPrefix(part, "pct=")
			fmt.Sscanf(pct, "%d", &analysis.Percentage)
			if analysis.Percentage < 100 {
				analysis.Issues = append(analysis.Issues, fmt.Sprintf("Only applying policy to %d%% of messages", analysis.Percentage))
			}
		} else if strings.HasPrefix(part, "rua=") {
			uris := strings.TrimPrefix(part, "rua=")
			for _, uri := range strings.Split(uris, ",") {
				analysis.ReportURI = append(analysis.ReportURI, uri)
			}
		} else if strings.HasPrefix(part, "ruf=") {
			uris := strings.TrimPrefix(part, "ruf=")
			for _, uri := range strings.Split(uris, ",") {
				analysis.ForensicURI = append(analysis.ForensicURI, uri)
			}
		}
	}

	// Check for issues
	if len(analysis.ReportURI) == 0 {
		analysis.Issues = append(analysis.Issues, "No aggregate report URI specified")
	}

	if analysis.Policy != "reject" && analysis.Policy != "quarantine" {
		analysis.Issues = append(analysis.Issues, "Consider using stronger policy ('quarantine' or 'reject') for better protection")
	}

	if analysis.SubdomainPolicy == "" {
		analysis.SubdomainPolicy = analysis.Policy
	}

	return analysis, nil
}

// AnalyzeDKIM analyzes DKIM records for a domain
func (a *Analyzer) AnalyzeDKIM(domain string) ([]*DKIMAnalysis, error) {
	// Try common selectors
	commonSelectors := []string{"default", "google", "mail", "dkim", "selector1", "selector2", "k1"}
	var results []*DKIMAnalysis

	for _, selector := range commonSelectors {
		selectorDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)
		records, err := a.getTXTRecords(selectorDomain)
		if err != nil || len(records) == 0 {
			continue
		}

		for _, record := range records {
			if strings.Contains(record, "v=DKIM1") {
				analysis := &DKIMAnalysis{
					Selector: selector,
					Record:   record,
					Valid:    true,
					Issues:   []string{},
				}

				// Parse key type
				if keyTypeMatch := regexp.MustCompile(`k=([a-zA-Z0-9]+)`).FindStringSubmatch(record); len(keyTypeMatch) > 1 {
					analysis.KeyType = keyTypeMatch[1]
				}

				// Check for public key
				if pubKeyMatch := regexp.MustCompile(`p=([A-Za-z0-9+/=]+)`).FindStringSubmatch(record); len(pubKeyMatch) > 1 {
					analysis.PublicKey = pubKeyMatch[1]
					if analysis.PublicKey == "" {
						analysis.Valid = false
						analysis.Issues = append(analysis.Issues, "Empty public key (revoked DKIM record)")
					}
				} else {
					analysis.Valid = false
					analysis.Issues = append(analysis.Issues, "Missing public key")
				}

				// Check for testing mode
				if strings.Contains(record, "t=y") {
					analysis.Issues = append(analysis.Issues, "DKIM record is in testing mode (t=y)")
				}

				results = append(results, analysis)
			}
		}
	}

	return results, nil
}

// AnalyzeMX analyzes MX records for a domain
func (a *Analyzer) AnalyzeMX(domain string) (*MXAnalysis, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	m.RecursionDesired = true

	r, _, err := a.Resolver.Exchange(m, a.Server)
	if err != nil {
		return nil, err
	}

	analysis := &MXAnalysis{
		Servers:       []string{},
		HasBackup:     false,
		AllSecure:     true,
		SecureServers: []string{},
		Issues:        []string{},
	}

	if len(r.Answer) == 0 {
		analysis.Issues = append(analysis.Issues, "No MX records found")
		return analysis, nil
	}

	if len(r.Answer) > 1 {
		analysis.HasBackup = true
	}

	// Extract MX servers
	for _, ans := range r.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			mxHost := strings.TrimSuffix(mx.Mx, ".")
			analysis.Servers = append(analysis.Servers, mxHost)

			// Check if MX server supports STARTTLS (simple check)
			if strings.Contains(strings.ToLower(mxHost), "google") ||
				strings.Contains(strings.ToLower(mxHost), "outlook") ||
				strings.Contains(strings.ToLower(mxHost), "microsoft") ||
				strings.Contains(strings.ToLower(mxHost), "protonmail") ||
				strings.Contains(strings.ToLower(mxHost), "zoho") {
				analysis.SecureServers = append(analysis.SecureServers, mxHost)
			} else {
				// We should actually test this by connecting to the SMTP server
				// and checking STARTTLS support, but that's beyond the scope here
				analysis.AllSecure = false
			}
		}
	}

	// Check for issues
	if len(analysis.Servers) == 0 {
		analysis.Issues = append(analysis.Issues, "No MX servers found")
	} else if !analysis.HasBackup {
		analysis.Issues = append(analysis.Issues, "Only one MX server found; Consider adding backup MX servers")
	}

	return analysis, nil
}

// AnalyzeCAA analyzes CAA records for a domain
func (a *Analyzer) AnalyzeCAA(domain string) (*CAAAnalysis, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCAA)
	m.RecursionDesired = true

	r, _, err := a.Resolver.Exchange(m, a.Server)
	if err != nil {
		return nil, err
	}

	analysis := &CAAAnalysis{
		Records:          []string{},
		HasIssueWildcard: false,
		IssueCAs:         []string{},
		IssueWildcardCAs: []string{},
		HasIODEF:         false,
		IODEFURIs:        []string{},
		Issues:           []string{},
	}

	if len(r.Answer) == 0 {
		return nil, fmt.Errorf("no CAA records found")
	}

	// Parse CAA records
	for _, ans := range r.Answer {
		if caa, ok := ans.(*dns.CAA); ok {
			caaStr := fmt.Sprintf("%s %s \"%s\"", caa.Tag, caa.Flag, caa.Value)
			analysis.Records = append(analysis.Records, caaStr)

			switch caa.Tag {
			case "issue":
				analysis.IssueCAs = append(analysis.IssueCAs, caa.Value)
			case "issuewild":
				analysis.HasIssueWildcard = true
				analysis.IssueWildcardCAs = append(analysis.IssueWildcardCAs, caa.Value)
			case "iodef":
				analysis.HasIODEF = true
				analysis.IODEFURIs = append(analysis.IODEFURIs, caa.Value)
			}
		}
	}

	// Check for issues
	if len(analysis.IssueCAs) == 0 {
		analysis.Issues = append(analysis.Issues, "No CAA issue property found")
	}

	if !analysis.HasIssueWildcard && len(analysis.IssueCAs) > 0 {
		analysis.Issues = append(analysis.Issues, "No issuewild property found; using issue constraints for wildcards")
	}

	if !analysis.HasIODEF {
		analysis.Issues = append(analysis.Issues, "No iodef property found for violation reports")
	}

	return analysis, nil
}

// Helper function to get TXT records
func (a *Analyzer) getTXTRecords(domain string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	m.RecursionDesired = true

	r, _, err := a.Resolver.Exchange(m, a.Server)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, ans := range r.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			records = append(records, strings.Join(txt.Txt, ""))
		}
	}

	return records, nil
}
