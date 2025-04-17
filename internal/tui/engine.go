package tui

import (
	"fmt"
	"time"

	"github.com/tldr-it-stepankutaj/dnsutils/internal/dns"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/subdomain"
)

func Analyze(domain string, modules []string, logFn func(string)) {
	logFn(fmt.Sprintf("[yellow]Start analyze domain:[white] %s", domain))
	resolver := dns.NewResolver()
	resolver.SetServer("8.8.8.8:53") // nebo volitelně z parametru

	results := &models.Results{
		Domain:        domain,
		Records:       make(map[string]interface{}),
		SubdomainData: make(map[string]models.SubdomainDetails),
	}

	for _, mod := range modules {
		switch mod {
		case "DNS":
			logFn("[blue]→ Getting A/AAAA/CNAME/MX/TXT records...")
			types := []string{"A", "AAAA", "CNAME", "MX", "TXT"}
			for _, t := range types {
				records, err := resolver.GetDNSRecords(domain, t)
				if err == nil && len(records) > 0 {
					results.Records[t] = records
					logFn(fmt.Sprintf("[green]✓ Found %d %s records", len(records), t))
				}
			}

		case "Subdomain":
			logFn("[blue]→ Discovering subdomains via certificates...")
			certFinder := subdomain.NewCertFinder()
			subs := certFinder.FindSubdomainsFromCertificates(domain)
			logFn(fmt.Sprintf("[green]✓ Found %d subdomains", len(subs)))

		default:
			logFn(fmt.Sprintf("[gray]→ Skipping module: %s", mod))
		}

		time.Sleep(500 * time.Millisecond) // vizuální efekt
	}

	logFn("[green]✔ Completed.")
}
