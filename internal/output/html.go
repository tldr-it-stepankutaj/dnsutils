// Package output provides formatters for scan results.
//
// NOTE: The following fields need to be added to models.Results:
//
//	WhoisInfo       *WhoisInfo                  `json:"whois_info,omitempty"`
//	ZoneTransfer    []ZoneTransferResult         `json:"zone_transfer,omitempty"`
//	DNSSEC          *DNSSECResult                `json:"dnssec,omitempty"`
//	TakeoverResults []TakeoverResult             `json:"takeover_results,omitempty"`
//	HeaderAnalysis  map[string]*HeaderAnalysis    `json:"header_analysis,omitempty"`
//	ReverseDNS      []ReverseDNSResult           `json:"reverse_dns,omitempty"`
//	CacheSnoop      []CacheSnoopResult           `json:"cache_snoop,omitempty"`
//
// Additionally, the following type needs to be created in models:
//
//	type ReverseDNSResult struct {
//	    IP       string `json:"ip"`
//	    Hostname string `json:"hostname"`
//	    Error    string `json:"error,omitempty"`
//	}
package output

import (
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
)

// HTML handles HTML report output.
type HTML struct{}

// NewHTML creates a new HTML formatter.
func NewHTML() *HTML {
	return &HTML{}
}

// SaveResultsToHTML generates a self-contained HTML report from scan results.
func (h *HTML) SaveResultsToHTML(results *models.Results, filename string) error {
	funcMap := template.FuncMap{
		"now": func() string {
			return time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
		},
		"join": strings.Join,
		"riskClass": func(risk string) string {
			switch strings.ToLower(risk) {
			case "high", "critical":
				return "risk-high"
			case "medium":
				return "risk-medium"
			case "low":
				return "risk-low"
			default:
				return "risk-info"
			}
		},
		"boolIcon": func(b bool) template.HTML {
			if b {
				return template.HTML(`<span class="icon-pass">&#10003;</span>`)
			}
			return template.HTML(`<span class="icon-fail">&#10007;</span>`)
		},
		"subdomainCount": func(results *models.Results) int {
			return len(results.Subdomains)
		},
		"recordTypeCount": func(records map[string]interface{}) int {
			return len(records)
		},
		"hasKey": func(m map[string]interface{}, key string) bool {
			_, ok := m[key]
			return ok
		},
		"dict": func(values ...interface{}) map[string]interface{} {
			d := make(map[string]interface{})
			for i := 0; i < len(values)-1; i += 2 {
				key, ok := values[i].(string)
				if ok {
					d[key] = values[i+1]
				}
			}
			return d
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("error parsing template: %v", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, results); err != nil {
		return fmt.Errorf("error executing template: %v", err)
	}

	return nil
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DNS Reconnaissance Report - {{ .Domain }}</title>
<style>
  :root {
    --bg-primary: #1a1a2e;
    --bg-secondary: #16213e;
    --bg-card: #0f3460;
    --bg-table-alt: #1a2744;
    --text-primary: #e0e0e0;
    --text-secondary: #a0a0b8;
    --accent: #e94560;
    --accent-secondary: #533483;
    --green: #4ecca3;
    --yellow: #ffc947;
    --red: #e94560;
    --blue: #0096c7;
    --border: #2a2a4a;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
  }

  .container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
  }

  /* Header */
  .report-header {
    background: linear-gradient(135deg, var(--bg-secondary), var(--bg-card));
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 40px;
    margin-bottom: 30px;
    text-align: center;
  }
  .report-header h1 {
    font-size: 2rem;
    color: var(--accent);
    margin-bottom: 8px;
  }
  .report-header .domain-name {
    font-size: 1.5rem;
    color: var(--text-primary);
    font-weight: 300;
    margin-bottom: 16px;
    word-break: break-all;
  }
  .report-header .scan-date {
    color: var(--text-secondary);
    font-size: 0.9rem;
  }

  /* Summary Stats */
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 30px;
  }
  .stat-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    text-align: center;
  }
  .stat-card .stat-value {
    font-size: 2rem;
    font-weight: 700;
    color: var(--accent);
  }
  .stat-card .stat-label {
    color: var(--text-secondary);
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-top: 4px;
  }

  /* Table of Contents */
  .toc {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 30px;
  }
  .toc h2 {
    color: var(--accent);
    margin-bottom: 12px;
    font-size: 1.1rem;
  }
  .toc ul {
    list-style: none;
    columns: 2;
    column-gap: 24px;
  }
  .toc li { margin-bottom: 6px; }
  .toc a {
    color: var(--blue);
    text-decoration: none;
    font-size: 0.95rem;
  }
  .toc a:hover { text-decoration: underline; }

  /* Sections */
  .section {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 24px;
  }
  .section h2 {
    color: var(--accent);
    font-size: 1.3rem;
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 2px solid var(--accent-secondary);
  }
  .section h3 {
    color: var(--text-primary);
    font-size: 1.05rem;
    margin: 16px 0 10px;
  }

  /* Tables */
  table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 16px;
    font-size: 0.9rem;
  }
  th {
    background: var(--bg-card);
    color: var(--accent);
    text-align: left;
    padding: 10px 14px;
    font-weight: 600;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.3px;
  }
  td {
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    word-break: break-all;
  }
  tr:nth-child(even) td { background: var(--bg-table-alt); }
  tr:hover td { background: rgba(233, 69, 96, 0.05); }

  /* Risk badges */
  .badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.8rem;
    font-weight: 600;
    text-transform: uppercase;
  }
  .risk-high   { background: rgba(233, 69, 96, 0.2); color: var(--red); }
  .risk-medium { background: rgba(255, 201, 71, 0.2); color: var(--yellow); }
  .risk-low    { background: rgba(78, 204, 163, 0.2); color: var(--green); }
  .risk-info   { background: rgba(0, 150, 199, 0.2); color: var(--blue); }

  .icon-pass { color: var(--green); font-weight: 700; }
  .icon-fail { color: var(--red); font-weight: 700; }

  .tag {
    display: inline-block;
    background: var(--bg-card);
    color: var(--text-secondary);
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.8rem;
    margin: 2px;
  }

  .finding-list {
    list-style: none;
    padding: 0;
  }
  .finding-list li {
    padding: 6px 0;
    border-bottom: 1px solid var(--border);
    font-size: 0.9rem;
  }
  .finding-list li:last-child { border-bottom: none; }
  .finding-list li::before {
    content: "\25B6";
    color: var(--accent);
    margin-right: 8px;
    font-size: 0.7rem;
  }

  .info-grid {
    display: grid;
    grid-template-columns: 180px 1fr;
    gap: 8px 16px;
    font-size: 0.9rem;
  }
  .info-label {
    color: var(--text-secondary);
    font-weight: 600;
  }
  .info-value {
    color: var(--text-primary);
    word-break: break-all;
  }

  /* Footer */
  .report-footer {
    text-align: center;
    padding: 20px;
    color: var(--text-secondary);
    font-size: 0.8rem;
    border-top: 1px solid var(--border);
    margin-top: 20px;
  }

  /* Print */
  @media print {
    body { background: #fff; color: #222; }
    .container { max-width: 100%; }
    .report-header { background: #f5f5f5; border: 1px solid #ccc; }
    .report-header h1 { color: #c0392b; }
    .section { background: #fff; border: 1px solid #ddd; break-inside: avoid; }
    .stat-card { background: #f9f9f9; border: 1px solid #ddd; }
    .toc { background: #f9f9f9; }
    th { background: #eee; color: #333; }
    td { color: #333; border-bottom-color: #ddd; }
    tr:nth-child(even) td { background: #f5f5f5; }
    .tag { background: #eee; color: #555; }
    a { color: #2980b9; }
    .report-footer { color: #888; border-top-color: #ddd; }
  }
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="report-header">
    <h1>DNS Reconnaissance Report</h1>
    <div class="domain-name">{{ .Domain }}</div>
    <div class="scan-date">Generated on {{ now }}</div>
  </div>

  <!-- Summary Stats -->
  <div class="summary-grid">
    <div class="stat-card">
      <div class="stat-value">{{ len .DomainIPs }}</div>
      <div class="stat-label">Domain IPs</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ recordTypeCount .Records }}</div>
      <div class="stat-label">Record Types</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ subdomainCount . }}</div>
      <div class="stat-label">Subdomains</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ len .CertSubdomains }}</div>
      <div class="stat-label">Cert Subdomains</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{ len .BruteSubdomains }}</div>
      <div class="stat-label">Brute-forced</div>
    </div>
    {{- if .SecurityAnalysis }}
    <div class="stat-card">
      <div class="stat-value">{{ .SecurityAnalysis.SecurityScore }}/100</div>
      <div class="stat-label">Security Score</div>
    </div>
    {{- end }}
  </div>

  <!-- Table of Contents -->
  <div class="toc">
    <h2>Table of Contents</h2>
    <ul>
      <li><a href="#domain-ips">Domain IPs</a></li>
      {{- if .Records }}
      <li><a href="#dns-records">DNS Records</a></li>
      {{- end }}
      {{- if .Subdomains }}
      <li><a href="#subdomains">Discovered Subdomains</a></li>
      {{- end }}
      {{- if .SubdomainData }}
      <li><a href="#subdomain-details">Subdomain Details &amp; SSL</a></li>
      {{- end }}
      {{- if .CertSubdomains }}
      <li><a href="#cert-subdomains">Certificate Subdomains</a></li>
      {{- end }}
      {{- if .WhoisInfo }}
      <li><a href="#whois">WHOIS Information</a></li>
      {{- end }}
      {{- if .ZoneTransfer }}
      <li><a href="#zone-transfer">Zone Transfer</a></li>
      {{- end }}
      {{- if .DNSSEC }}
      <li><a href="#dnssec">DNSSEC Validation</a></li>
      {{- end }}
      {{- if .TakeoverResults }}
      <li><a href="#takeover">Subdomain Takeover</a></li>
      {{- end }}
      {{- if .HeaderAnalysis }}
      <li><a href="#headers">HTTP Security Headers</a></li>
      {{- end }}
      {{- if .ReverseDNS }}
      <li><a href="#reverse-dns">Reverse DNS</a></li>
      {{- end }}
      {{- if .SecurityAnalysis }}
      <li><a href="#email-security">Email Security Analysis</a></li>
      {{- end }}
      {{- if .CloudAnalysis }}
      <li><a href="#cloud">Cloud Infrastructure</a></li>
      {{- end }}
      {{- if .CacheSnoop }}
      <li><a href="#cache-snoop">DNS Cache Snooping</a></li>
      {{- end }}
    </ul>
  </div>

  <!-- Domain IPs -->
  <div class="section" id="domain-ips">
    <h2>Domain IPs</h2>
    {{- if .DomainIPs }}
    <table>
      <thead><tr><th>#</th><th>IP Address</th></tr></thead>
      <tbody>
      {{- range $i, $ip := .DomainIPs }}
        <tr><td>{{ $i }}</td><td>{{ $ip }}</td></tr>
      {{- end }}
      </tbody>
    </table>
    {{- else }}
    <p>No IP addresses resolved.</p>
    {{- end }}
  </div>

  <!-- DNS Records -->
  {{- if .Records }}
  <div class="section" id="dns-records">
    <h2>DNS Records</h2>
    {{- range $type, $records := .Records }}
    <h3>{{ $type }}</h3>
    <table>
      <thead><tr><th>Value</th></tr></thead>
      <tbody>
      {{- if eq (printf "%T" $records) "[]interface {}" }}
        {{- range $records }}
        <tr><td>{{ . }}</td></tr>
        {{- end }}
      {{- else }}
        <tr><td>{{ $records }}</td></tr>
      {{- end }}
      </tbody>
    </table>
    {{- end }}
  </div>
  {{- end }}

  <!-- Discovered Subdomains -->
  {{- if .Subdomains }}
  <div class="section" id="subdomains">
    <h2>Discovered Subdomains</h2>
    <table>
      <thead><tr><th>Subdomain</th><th>IP Address</th></tr></thead>
      <tbody>
      {{- range .Subdomains }}
        <tr><td>{{ .Name }}</td><td>{{ .IP }}</td></tr>
      {{- end }}
      </tbody>
    </table>
  </div>
  {{- end }}

  <!-- Subdomain Details & SSL -->
  {{- if .SubdomainData }}
  <div class="section" id="subdomain-details">
    <h2>Subdomain Details &amp; SSL Certificates</h2>
    <table>
      <thead><tr><th>Subdomain</th><th>IP</th><th>ASN</th><th>Open Services</th><th>SSL CN</th><th>SSL Issuer</th><th>SSL Expiry</th></tr></thead>
      <tbody>
      {{- range $name, $detail := .SubdomainData }}
        <tr>
          <td>{{ $name }}</td>
          <td>{{ $detail.IP }}</td>
          <td>{{ $detail.ASN }}</td>
          <td>
            {{- range $detail.OpenServices }}<span class="tag">{{ . }}</span>{{ end }}
          </td>
          {{- if $detail.SSLInfo }}
          <td>{{ $detail.SSLInfo.CommonName }}</td>
          <td>{{ $detail.SSLInfo.Issuer }}</td>
          <td>{{ $detail.SSLInfo.Expiry }}</td>
          {{- else }}
          <td colspan="3" style="color:var(--text-secondary);">No SSL</td>
          {{- end }}
        </tr>
      {{- end }}
      </tbody>
    </table>
  </div>
  {{- end }}

  <!-- Certificate Subdomains -->
  {{- if .CertSubdomains }}
  <div class="section" id="cert-subdomains">
    <h2>Certificate Transparency Subdomains</h2>
    <table>
      <thead><tr><th>#</th><th>Subdomain</th></tr></thead>
      <tbody>
      {{- range $i, $sub := .CertSubdomains }}
        <tr><td>{{ $i }}</td><td>{{ $sub }}</td></tr>
      {{- end }}
      </tbody>
    </table>
  </div>
  {{- end }}

  <!-- WHOIS Information -->
  {{- if .WhoisInfo }}
  <div class="section" id="whois">
    <h2>WHOIS Information</h2>
    <div class="info-grid">
      <div class="info-label">Registrar</div>
      <div class="info-value">{{ .WhoisInfo.Registrar }}</div>
      <div class="info-label">Organization</div>
      <div class="info-value">{{ .WhoisInfo.Organization }}</div>
      <div class="info-label">Country</div>
      <div class="info-value">{{ .WhoisInfo.Country }}</div>
      <div class="info-label">Created</div>
      <div class="info-value">{{ .WhoisInfo.CreatedDate }}</div>
      <div class="info-label">Updated</div>
      <div class="info-value">{{ .WhoisInfo.UpdatedDate }}</div>
      <div class="info-label">Expires</div>
      <div class="info-value">{{ .WhoisInfo.ExpiryDate }}</div>
      <div class="info-label">DNSSEC</div>
      <div class="info-value">{{ .WhoisInfo.DNSSEC }}</div>
    </div>
    {{- if .WhoisInfo.NameServers }}
    <h3>Name Servers</h3>
    <table>
      <thead><tr><th>Name Server</th></tr></thead>
      <tbody>
      {{- range .WhoisInfo.NameServers }}
        <tr><td>{{ . }}</td></tr>
      {{- end }}
      </tbody>
    </table>
    {{- end }}
  </div>
  {{- end }}

  <!-- Zone Transfer -->
  {{- if .ZoneTransfer }}
  <div class="section" id="zone-transfer">
    <h2>Zone Transfer (AXFR)</h2>
    <table>
      <thead><tr><th>Nameserver</th><th>Vulnerable</th><th>Records</th><th>Error</th></tr></thead>
      <tbody>
      {{- range .ZoneTransfer }}
        <tr>
          <td>{{ .Nameserver }}</td>
          <td>{{ boolIcon .Vulnerable }}</td>
          <td>
            {{- if .Records }}
              {{- range .Records }}<div>{{ . }}</div>{{ end }}
            {{- else }}-{{ end }}
          </td>
          <td>{{ .Error }}</td>
        </tr>
      {{- end }}
      </tbody>
    </table>
  </div>
  {{- end }}

  <!-- DNSSEC Validation -->
  {{- if .DNSSEC }}
  <div class="section" id="dnssec">
    <h2>DNSSEC Validation</h2>
    <div class="info-grid">
      <div class="info-label">Enabled</div>
      <div class="info-value">{{ boolIcon .DNSSEC.Enabled }}</div>
      <div class="info-label">Valid</div>
      <div class="info-value">{{ boolIcon .DNSSEC.Valid }}</div>
      <div class="info-label">Algorithm</div>
      <div class="info-value">{{ .DNSSEC.Algorithm }}</div>
      <div class="info-label">DS Records</div>
      <div class="info-value">{{ .DNSSEC.DSRecords }}</div>
      <div class="info-label">DNSKEYs</div>
      <div class="info-value">{{ .DNSSEC.DNSKEYs }}</div>
    </div>
    {{- if .DNSSEC.KeyTypes }}
    <h3>Key Types</h3>
    <ul class="finding-list">
    {{- range .DNSSEC.KeyTypes }}
      <li>{{ . }}</li>
    {{- end }}
    </ul>
    {{- end }}
    {{- if .DNSSEC.Issues }}
    <h3>Issues</h3>
    <ul class="finding-list">
    {{- range .DNSSEC.Issues }}
      <li>{{ . }}</li>
    {{- end }}
    </ul>
    {{- end }}
  </div>
  {{- end }}

  <!-- Subdomain Takeover -->
  {{- if .TakeoverResults }}
  <div class="section" id="takeover">
    <h2>Subdomain Takeover Findings</h2>
    <table>
      <thead><tr><th>Subdomain</th><th>CNAME</th><th>Service</th><th>Vulnerable</th><th>Risk</th><th>Fingerprint</th></tr></thead>
      <tbody>
      {{- range .TakeoverResults }}
        <tr>
          <td>{{ .Subdomain }}</td>
          <td>{{ .CNAME }}</td>
          <td>{{ .Service }}</td>
          <td>{{ boolIcon .Vulnerable }}</td>
          <td><span class="badge {{ riskClass .Risk }}">{{ .Risk }}</span></td>
          <td>{{ .Fingerprint }}</td>
        </tr>
      {{- end }}
      </tbody>
    </table>
  </div>
  {{- end }}

  <!-- HTTP Security Headers -->
  {{- if .HeaderAnalysis }}
  <div class="section" id="headers">
    <h2>HTTP Security Headers</h2>
    {{- range $url, $analysis := .HeaderAnalysis }}
    <h3>{{ $analysis.URL }}</h3>
    <div class="info-grid" style="margin-bottom:12px;">
      <div class="info-label">Status Code</div>
      <div class="info-value">{{ $analysis.StatusCode }}</div>
      {{- if $analysis.Server }}
      <div class="info-label">Server</div>
      <div class="info-value">{{ $analysis.Server }}</div>
      {{- end }}
      {{- if $analysis.PoweredBy }}
      <div class="info-label">Powered By</div>
      <div class="info-value">{{ $analysis.PoweredBy }}</div>
      {{- end }}
    </div>
    {{- if $analysis.SecurityHeaders }}
    <h3>Present Headers</h3>
    <table>
      <thead><tr><th>Header</th><th>Value</th></tr></thead>
      <tbody>
      {{- range $hdr, $val := $analysis.SecurityHeaders }}
        <tr><td>{{ $hdr }}</td><td>{{ $val }}</td></tr>
      {{- end }}
      </tbody>
    </table>
    {{- end }}
    {{- if $analysis.MissingHeaders }}
    <h3>Missing Headers</h3>
    <ul class="finding-list">
    {{- range $analysis.MissingHeaders }}
      <li>{{ . }}</li>
    {{- end }}
    </ul>
    {{- end }}
    {{- if $analysis.Technologies }}
    <h3>Detected Technologies</h3>
    <div>
      {{- range $analysis.Technologies }}<span class="tag">{{ . }}</span>{{ end }}
    </div>
    {{- end }}
    {{- if $analysis.Findings }}
    <h3>Findings</h3>
    <ul class="finding-list">
    {{- range $analysis.Findings }}
      <li>{{ . }}</li>
    {{- end }}
    </ul>
    {{- end }}
    {{- end }}
  </div>
  {{- end }}

  <!-- Reverse DNS -->
  {{- if .ReverseDNS }}
  <div class="section" id="reverse-dns">
    <h2>Reverse DNS Results</h2>
    <table>
      <thead><tr><th>IP Address</th><th>Hostname</th><th>Error</th></tr></thead>
      <tbody>
      {{- range .ReverseDNS }}
        <tr>
          <td>{{ .IP }}</td>
          <td>{{ .Hostname }}</td>
          <td>{{ .Error }}</td>
        </tr>
      {{- end }}
      </tbody>
    </table>
  </div>
  {{- end }}

  <!-- Email Security Analysis -->
  {{- if .SecurityAnalysis }}
  <div class="section" id="email-security">
    <h2>Email Security Analysis</h2>
    <div class="info-grid" style="margin-bottom:16px;">
      <div class="info-label">Security Score</div>
      <div class="info-value" style="font-weight:700;color:var(--accent);">{{ .SecurityAnalysis.SecurityScore }} / 100</div>
    </div>

    {{- if .SecurityAnalysis.SPFRecord }}
    <h3>SPF Record</h3>
    <div class="info-grid" style="margin-bottom:8px;">
      <div class="info-label">Record</div>
      <div class="info-value" style="font-family:monospace;font-size:0.85rem;">{{ .SecurityAnalysis.SPFRecord.Record }}</div>
      <div class="info-label">Valid</div>
      <div class="info-value">{{ boolIcon .SecurityAnalysis.SPFRecord.Valid }}</div>
      <div class="info-label">Policy</div>
      <div class="info-value">{{ .SecurityAnalysis.SPFRecord.Policy }}</div>
      {{- if .SecurityAnalysis.SPFRecord.HasRedirect }}
      <div class="info-label">Redirect</div>
      <div class="info-value">{{ .SecurityAnalysis.SPFRecord.RedirectDomain }}</div>
      {{- end }}
    </div>
    {{- if .SecurityAnalysis.SPFRecord.Includes }}
    <h3>SPF Includes</h3>
    <div>
      {{- range .SecurityAnalysis.SPFRecord.Includes }}<span class="tag">{{ . }}</span>{{ end }}
    </div>
    {{- end }}
    {{- if .SecurityAnalysis.SPFRecord.Issues }}
    <h3>SPF Issues</h3>
    <ul class="finding-list">
    {{- range .SecurityAnalysis.SPFRecord.Issues }}
      <li>{{ . }}</li>
    {{- end }}
    </ul>
    {{- end }}
    {{- end }}

    {{- if .SecurityAnalysis.DMARCRecord }}
    <h3>DMARC Record</h3>
    <div class="info-grid" style="margin-bottom:8px;">
      <div class="info-label">Record</div>
      <div class="info-value" style="font-family:monospace;font-size:0.85rem;">{{ .SecurityAnalysis.DMARCRecord.Record }}</div>
      <div class="info-label">Valid</div>
      <div class="info-value">{{ boolIcon .SecurityAnalysis.DMARCRecord.Valid }}</div>
      <div class="info-label">Policy</div>
      <div class="info-value">{{ .SecurityAnalysis.DMARCRecord.Policy }}</div>
      <div class="info-label">Subdomain Policy</div>
      <div class="info-value">{{ .SecurityAnalysis.DMARCRecord.SubdomainPolicy }}</div>
      <div class="info-label">Percentage</div>
      <div class="info-value">{{ .SecurityAnalysis.DMARCRecord.Percentage }}%</div>
    </div>
    {{- if .SecurityAnalysis.DMARCRecord.Issues }}
    <h3>DMARC Issues</h3>
    <ul class="finding-list">
    {{- range .SecurityAnalysis.DMARCRecord.Issues }}
      <li>{{ . }}</li>
    {{- end }}
    </ul>
    {{- end }}
    {{- end }}

    {{- if .SecurityAnalysis.DKIMRecords }}
    <h3>DKIM Records</h3>
    <table>
      <thead><tr><th>Selector</th><th>Valid</th><th>Key Type</th><th>Issues</th></tr></thead>
      <tbody>
      {{- range .SecurityAnalysis.DKIMRecords }}
        <tr>
          <td>{{ .Selector }}</td>
          <td>{{ boolIcon .Valid }}</td>
          <td>{{ .KeyType }}</td>
          <td>
            {{- if .Issues }}{{ join .Issues "; " }}{{ else }}-{{ end }}
          </td>
        </tr>
      {{- end }}
      </tbody>
    </table>
    {{- end }}

    {{- if .SecurityAnalysis.MXAnalysis }}
    <h3>MX Analysis</h3>
    <div class="info-grid" style="margin-bottom:8px;">
      <div class="info-label">Has Backup</div>
      <div class="info-value">{{ boolIcon .SecurityAnalysis.MXAnalysis.HasBackup }}</div>
      <div class="info-label">All Secure</div>
      <div class="info-value">{{ boolIcon .SecurityAnalysis.MXAnalysis.AllSecure }}</div>
    </div>
    {{- if .SecurityAnalysis.MXAnalysis.Servers }}
    <table>
      <thead><tr><th>MX Server</th></tr></thead>
      <tbody>
      {{- range .SecurityAnalysis.MXAnalysis.Servers }}
        <tr><td>{{ . }}</td></tr>
      {{- end }}
      </tbody>
    </table>
    {{- end }}
    {{- if .SecurityAnalysis.MXAnalysis.Issues }}
    <h3>MX Issues</h3>
    <ul class="finding-list">
    {{- range .SecurityAnalysis.MXAnalysis.Issues }}
      <li>{{ . }}</li>
    {{- end }}
    </ul>
    {{- end }}
    {{- end }}

    {{- if .SecurityAnalysis.CAAAnalysis }}
    <h3>CAA Records</h3>
    <div class="info-grid" style="margin-bottom:8px;">
      <div class="info-label">Issue Wildcard</div>
      <div class="info-value">{{ boolIcon .SecurityAnalysis.CAAAnalysis.HasIssueWildcard }}</div>
      <div class="info-label">Has IODEF</div>
      <div class="info-value">{{ boolIcon .SecurityAnalysis.CAAAnalysis.HasIODEF }}</div>
    </div>
    {{- if .SecurityAnalysis.CAAAnalysis.IssueCAs }}
    <table>
      <thead><tr><th>Authorized CA</th></tr></thead>
      <tbody>
      {{- range .SecurityAnalysis.CAAAnalysis.IssueCAs }}
        <tr><td>{{ . }}</td></tr>
      {{- end }}
      </tbody>
    </table>
    {{- end }}
    {{- if .SecurityAnalysis.CAAAnalysis.Issues }}
    <h3>CAA Issues</h3>
    <ul class="finding-list">
    {{- range .SecurityAnalysis.CAAAnalysis.Issues }}
      <li>{{ . }}</li>
    {{- end }}
    </ul>
    {{- end }}
    {{- end }}

    {{- if .SecurityAnalysis.Recommendations }}
    <h3>Recommendations</h3>
    <ul class="finding-list">
    {{- range .SecurityAnalysis.Recommendations }}
      <li>{{ . }}</li>
    {{- end }}
    </ul>
    {{- end }}
  </div>
  {{- end }}

  <!-- Cloud Infrastructure -->
  {{- if .CloudAnalysis }}
  <div class="section" id="cloud">
    <h2>Cloud Infrastructure</h2>
    <div class="summary-grid" style="margin-bottom:16px;">
      <div class="stat-card">
        <div class="stat-value">{{ .CloudAnalysis.TotalProviders }}</div>
        <div class="stat-label">Providers</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{{ .CloudAnalysis.TotalServices }}</div>
        <div class="stat-label">Services</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{{ .CloudAnalysis.TotalOrphaned }}</div>
        <div class="stat-label">Orphaned Resources</div>
      </div>
      <div class="stat-card">
        <div class="stat-value"><span class="badge {{ riskClass .CloudAnalysis.RiskLevel }}">{{ .CloudAnalysis.RiskLevel }}</span></div>
        <div class="stat-label">Risk Level</div>
      </div>
    </div>

    {{- range $name, $provider := .CloudAnalysis.Providers }}
    <h3>{{ $provider.Provider }} <span class="badge {{ riskClass $provider.Confidence }}">{{ $provider.Confidence }} confidence</span></h3>
    <div class="info-grid" style="margin-bottom:8px;">
      {{- if $provider.Verification }}
      <div class="info-label">Verification</div>
      <div class="info-value">{{ $provider.Verification }}</div>
      {{- end }}
    </div>
    {{- if $provider.Services }}
    <div style="margin-bottom:8px;">
      <strong style="color:var(--text-secondary);font-size:0.85rem;">Services:</strong>
      {{- range $provider.Services }}<span class="tag">{{ . }}</span>{{ end }}
    </div>
    {{- end }}
    {{- if $provider.Subdomains }}
    <div style="margin-bottom:8px;">
      <strong style="color:var(--text-secondary);font-size:0.85rem;">Subdomains:</strong>
      {{- range $provider.Subdomains }}<span class="tag">{{ . }}</span>{{ end }}
    </div>
    {{- end }}
    {{- if $provider.IPs }}
    <div style="margin-bottom:8px;">
      <strong style="color:var(--text-secondary);font-size:0.85rem;">IPs:</strong>
      {{- range $provider.IPs }}<span class="tag">{{ . }}</span>{{ end }}
    </div>
    {{- end }}
    {{- if $provider.Orphaned }}
    <div style="margin-bottom:8px;">
      <strong style="color:var(--red);font-size:0.85rem;">Orphaned:</strong>
      {{- range $provider.Orphaned }}<span class="tag" style="border:1px solid var(--red);">{{ . }}</span>{{ end }}
    </div>
    {{- end }}
    {{- end }}

    {{- if .CloudAnalysis.Recommendations }}
    <h3>Recommendations</h3>
    <ul class="finding-list">
    {{- range .CloudAnalysis.Recommendations }}
      <li>{{ . }}</li>
    {{- end }}
    </ul>
    {{- end }}
  </div>
  {{- end }}

  <!-- DNS Cache Snooping -->
  {{- if .CacheSnoop }}
  <div class="section" id="cache-snoop">
    <h2>DNS Cache Snooping</h2>
    <table>
      <thead><tr><th>Server</th><th>Domain</th><th>Cached</th><th>TTL</th></tr></thead>
      <tbody>
      {{- range .CacheSnoop }}
        <tr>
          <td>{{ .Server }}</td>
          <td>{{ .Domain }}</td>
          <td>{{ boolIcon .Cached }}</td>
          <td>{{ .TTL }}</td>
        </tr>
      {{- end }}
      </tbody>
    </table>
  </div>
  {{- end }}

  <!-- Footer -->
  <div class="report-footer">
    <p>Report generated by <strong>dnsutils</strong> on {{ now }}</p>
    <p>This report is intended for authorized security assessments only.</p>
  </div>

</div>
</body>
</html>`
