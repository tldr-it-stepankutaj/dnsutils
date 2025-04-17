package scanner

import (
	"github.com/tldr-it-stepankutaj/dnsutils/internal/cloud"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/dns"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/security"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/ssl"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/subdomain"
)

func RunModule(domain string, module string, dnsServer string, output ScanOutput, results *models.Results) {
	switch module {
	case "DNS":
		output.Printf("[cyan]Running DNS module\n")
		resolver := dns.NewResolver()
		resolver.SetServer(dnsServer)

		ips := resolver.GetIPs(domain)
		if len(ips) > 0 {
			results.DomainIPs = ips
			output.Printf("[green]Found %d IPs\n", len(ips))
			for _, ip := range ips {
				output.Printf("[white] → %s\n", ip)
			}
		} else {
			output.Printf("[red]No IPs found\n")
		}
	case "Subdomain":
		output.Printf("[cyan]Running Subdomain module\n")
		certFinder := subdomain.NewCertFinder()
		subs := certFinder.FindSubdomainsFromCertificates(domain)
		if len(subs) > 0 {
			results.CertSubdomains = subs
			output.Printf("[green]Found %d cert-based subdomains\n", len(subs))
			for _, s := range subs {
				output.Printf("[white] → %s\n", s)
			}
		} else {
			output.Printf("[red]No subdomains found\n")
		}
	case "SSL":
		output.Printf("[cyan]Running SSL module\n")
		sslCert := ssl.NewCertificate()
		info := sslCert.GetSSLInfo(domain, 443)
		if info != nil {
			results.SubdomainData[domain] = models.SubdomainDetails{
				SSLInfo: info,
			}
			output.Printf("[green]SSL info fetched.\n")

			if info.Issuer != "" {
				output.Printf("[white] → Issuer: %s\n", info.Issuer)
			} else {
				output.Printf("[white] → Issuer: [unknown]\n")
			}

			output.Printf("[white] → Expiry: %s\n", info.Expiry)
		} else {
			output.Printf("[red]SSL info not available.\n")
		}
	case "Cloud":
		output.Println("[yellow]Running Cloud module")
		cloudResult, err := cloud.NewDetector(dnsServer).AnalyzeCloudInfrastructure(domain, results)
		if err == nil {
			results.CloudAnalysis = cloudResult
			output.Printf("[green]Detected %d cloud providers\n", cloudResult.TotalProviders)
		}
	case "Security":
		output.Println("[yellow]Running Security module")
		res, err := security.NewAnalyzer(dnsServer).AnalyzeDomain(domain)
		if err == nil && res != nil {
			results.SecurityAnalysis = res
			output.Printf("[green]Security score: %d/100\n", res.SecurityScore)
		}
	default:
		output.Printf("[red]Unknown module: %s\n", module)
	}
}
