package output

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
)

// Colors for console output
const (
	ColorReset  = "\033[0m"
	ColorBlue   = "\033[34m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorRed    = "\033[31m"
	ColorBold   = "\033[1m"
)

// Console handles console output formatting
type Console struct{}

// NewConsole creates a new console formatter
func NewConsole() *Console {
	return &Console{}
}

// PrintBanner prints the tool banner
func (c *Console) PrintBanner() {
	banner := `
╔═══════════════════════════════════════════════════════╗
║               DNS Reconnaissance Tool                 ║
╚═══════════════════════════════════════════════════════╝
`
	fmt.Println(ColorBlue + banner + ColorReset)
}

// formatServiceText breaks long service text into multiple lines
// by inserting newlines after every 5 words
func (c *Console) formatServiceText(text string) string {
	words := strings.Fields(text)

	var formattedParts []string
	for i := 0; i < len(words); i += 5 {
		end := i + 5
		if end > len(words) {
			end = len(words)
		}
		formattedParts = append(formattedParts, strings.Join(words[i:end], " "))
	}

	return strings.Join(formattedParts, "\n")
}

// PrintResults prints the scan results to the console
func (c *Console) PrintResults(results *models.Results) {
	// Print domain information
	fmt.Printf("%s[+] Scanning domain: %s%s\n", ColorGreen, results.Domain, ColorReset)

	// Print domain IPs
	if len(results.DomainIPs) > 0 {
		fmt.Printf("%s[+] Domain IP addresses: %s%s\n", ColorGreen, strings.Join(results.DomainIPs, ", "), ColorReset)
	} else {
		fmt.Printf("%s[!] Could not get IP addresses for domain%s\n", ColorYellow, ColorReset)
	}

	// Print DNS records
	for recordType, records := range results.Records {
		fmt.Printf("\n%s%sDNS %s Records:%s\n", ColorBold, ColorBlue, recordType, ColorReset)

		table := tablewriter.NewWriter(os.Stdout)
		table.SetAutoWrapText(false)
		table.SetAutoFormatHeaders(true)
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetBorder(true)
		table.SetRowLine(true)

		switch recordType {
		case "A", "AAAA":
			table.SetHeader([]string{"IP Address"})
			if recordList, ok := records.([]interface{}); ok {
				for _, record := range recordList {
					if r, ok := record.(*models.GenericRecord); ok {
						table.Append([]string{r.Value})
					}
				}
			}
		case "MX":
			table.SetHeader([]string{"Preference", "Exchange"})
			if recordList, ok := records.([]interface{}); ok {
				for _, record := range recordList {
					if r, ok := record.(*models.MXRecord); ok {
						table.Append([]string{
							fmt.Sprintf("%d", r.Preference),
							r.Exchange,
						})
					}
				}
			}
		case "SOA":
			table.SetHeader([]string{"Primary NS", "Admin Email", "Serial", "Refresh", "Retry", "Expire", "Minimum"})
			if recordList, ok := records.([]interface{}); ok {
				for _, record := range recordList {
					if r, ok := record.(*models.SOARecord); ok {
						table.Append([]string{
							r.MName,
							r.RName,
							fmt.Sprintf("%d", r.Serial),
							fmt.Sprintf("%d", r.Refresh),
							fmt.Sprintf("%d", r.Retry),
							fmt.Sprintf("%d", r.Expire),
							fmt.Sprintf("%d", r.Minimum),
						})
					}
				}
			}
		case "CNAME":
			table.SetHeader([]string{"Target"})
			if recordList, ok := records.([]interface{}); ok {
				for _, record := range recordList {
					if r, ok := record.(*models.CNAMERecord); ok {
						table.Append([]string{r.Target})
					}
				}
			}
		case "NS":
			table.SetHeader([]string{"Nameserver"})
			if recordList, ok := records.([]interface{}); ok {
				for _, record := range recordList {
					if r, ok := record.(*models.NSRecord); ok {
						table.Append([]string{r.NameServer})
					}
				}
			}
		case "TXT":
			table.SetHeader([]string{"Text"})
			if recordList, ok := records.([]interface{}); ok {
				for _, record := range recordList {
					if r, ok := record.(*models.TXTRecord); ok {
						table.Append([]string{r.Text})
					}
				}
			}
		}

		table.Render()
	}

	// Print subdomains
	if len(results.Subdomains) > 0 {
		fmt.Printf("\n%s%sDiscovered Subdomains (%d):%s\n", ColorBold, ColorBlue, len(results.Subdomains), ColorReset)

		// Sort subdomains alphabetically
		sort.Slice(results.Subdomains, func(i, j int) bool {
			return results.Subdomains[i].Name < results.Subdomains[j].Name
		})

		// Create a table with better multi-line support
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Subdomain", "IP Address", "ASN", "Open Services"})
		table.SetAutoWrapText(false)
		table.SetAutoFormatHeaders(true)
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetBorder(true)
		table.SetRowLine(true) // Add lines between rows
		table.SetColWidth(60)  // Set a reasonable column width

		for _, subdomain := range results.Subdomains {
			asn := ""
			services := ""

			if details, ok := results.SubdomainData[subdomain.Name]; ok {
				asn = details.ASN

				// Format services to be more table-friendly
				if len(details.OpenServices) > 0 {
					// Format each service with line breaks
					var formattedServices []string
					for _, service := range details.OpenServices {
						// Clean up the service string - replace multiple spaces with single space
						service = strings.Join(strings.Fields(service), " ")
						// Add line breaks after every 5 words
						formattedServices = append(formattedServices, c.formatServiceText(service))
					}
					services = strings.Join(formattedServices, "\n\n") // Double newline between different services
				}
			}

			table.Append([]string{
				subdomain.Name,
				subdomain.IP,
				asn,
				services,
			})
		}

		table.Render()

		// Print SSL certificates
		c.PrintSSLCertificates(results)
	} else {
		fmt.Printf("\n%s[!] No subdomains discovered%s\n", ColorYellow, ColorReset)
	}
}

// PrintSSLCertificates prints SSL certificate information
func (c *Console) PrintSSLCertificates(results *models.Results) {
	var sslInfos []*models.SSLInfo
	var domains []string

	for subdomain, details := range results.SubdomainData {
		if details.SSLInfo != nil {
			sslInfos = append(sslInfos, details.SSLInfo)
			domains = append(domains, subdomain)
		}
	}

	if len(sslInfos) > 0 {
		fmt.Printf("\n%s%sSSL Certificates (%d):%s\n", ColorBold, ColorBlue, len(sslInfos), ColorReset)

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Subdomain", "Common Name", "Issuer", "Expiry"})
		table.SetAutoWrapText(false)
		table.SetAutoFormatHeaders(true)
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetBorder(true)
		table.SetColWidth(40)

		for i, info := range sslInfos {
			table.Append([]string{
				domains[i],
				info.CommonName,
				info.Issuer,
				info.Expiry,
			})
		}

		table.Render()
	} else {
		fmt.Printf("\n%s[!] No SSL certificates found%s\n", ColorYellow, ColorReset)
	}
}

// PrintProgress prints a progress message
func (c *Console) PrintProgress(message string) {
	fmt.Printf("%s[*] %s%s\n", ColorBlue, message, ColorReset)
}

// PrintSuccess prints a success message
func (c *Console) PrintSuccess(message string) {
	fmt.Printf("%s[+] %s%s\n", ColorGreen, message, ColorReset)
}

// PrintWarning prints a warning message
func (c *Console) PrintWarning(message string) {
	fmt.Printf("%s[!] %s%s\n", ColorYellow, message, ColorReset)
}

// PrintError prints an error message
func (c *Console) PrintError(message string) {
	fmt.Printf("%s[!] %s%s\n", ColorRed, message, ColorReset)
}
